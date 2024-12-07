from config import *
from queue import Queue
from slither import Slither
from slither.core.declarations import Contract
from typing import Tuple, List
from slither.core.expressions import TypeConversion, Identifier, AssignmentOperation
from slither.core.solidity_types import UserDefinedType

logger = get_logger()


@logger.catch()
def analysis_depend_contract(file_path: str, _contract_name: str, _solc_version: str, _solc_path) -> (Tuple)[List, Slither]:
    """Phân tích các hợp đồng phụ thuộc của một hợp đồng Solidity.
    
    Tham số:
        - file_path (str): Đường dẫn đến tệp hợp đồng Solidity.
        - _contract_name (str): Tên của hợp đồng chính cần phân tích.
        - _solc_version (str): Phiên bản của trình biên dịch Solidity.
        - _solc_path: Đường dẫn đến trình biên dịch Solidity.
    
    Trả về:
        
        Tuple[List, Slither]:
        
            - List: Danh sách các hợp đồng phụ thuộc cần triển khai.
            - Slither: Đối tượng Slither chứa thông tin phân tích hợp đồng.
    """
    res = set()  # Contracts that need to be deployed
    sl = Slither(file_path, solc=_solc_path)
    to_be_deep_analysis = Queue()  # Each item in this queue needs to be analyzed
    to_be_deep_analysis.put(_contract_name)
    while not to_be_deep_analysis.empty():
        c = to_be_deep_analysis.get()
        contract = sl.get_contract_from_name(c)
        if len(contract) != 1:
            # logger.warning("理论上, 根据合约名字, 只能找到一个合约")
            logger.warning("In theory, only one contract should be found by its name.")

            return [], sl
        contract = contract[0]
# 1. Analyze state variables that are written
        for v in contract.all_state_variables_written:
            if not v.initialized and isinstance(v.type, UserDefinedType) and hasattr(v.type, "type") and isinstance(
                    v.type.type, Contract):
                res.add(v.type.type.name)
                # logger.debug("通过分析合约内被写入的状态变量, 发现依赖的合约: {}".format(v.type.type.name))
                logger.debug("Dependency contract found by analyzing written state variables: {}".format(v.type.type.name))
        for f in contract.functions:
# 2. Analyze the parameters of the functions in the contract
            for p in f.parameters:
                if isinstance(p.type, UserDefinedType) and hasattr(p.type, "type") and isinstance(p.type.type,
                                                                                                  Contract):
                    res.add(p.type.type.name)
                    # logger.debug("通过分析合约内函数的参数, 发现依赖的合约: {}".format(p.type.type.name))
                    logger.debug("Dependency contract found by analyzing function parameters: {}".format(p.type.type.name))
            # 3. Analyze variables written by functions, if it's a contract type, it also needs to be deployed
            for v in f.variables_written:
                if hasattr(v, "type") and isinstance(v.type, UserDefinedType) and hasattr(v.type,
                                                                                          "type") and isinstance(
                    v.type.type, Contract):
                    res.add(v.type.type.name)
                    logger.debug("Dependency contract found by analyzing written variables (both local and state): {}".format(v.type.type.name))
                    # logger.debug("通过分析函数的写入变量(局部和状态都算), 发现依赖的合约: {}".format(v.type.type.name))
        # 4. Analyze inheritance within the contract and add to the analysis queue
        for inherit in contract.inheritance:
            if inherit.name not in res:
                to_be_deep_analysis.put(inherit.name)
    if _contract_name in res:
        # logger.debug("主合约被分析到了依赖合约中, 需要移除")
        logger.debug("The main contract is included in the dependency list and will be removed.")

        res.remove(_contract_name)
    # 5. Check the bytecode of dependent contracts and remove empty contracts
    compilation_unit = sl.compilation_units[0].crytic_compile_compilation_unit
    for depend_c in res.copy():
        if compilation_unit.bytecode_runtime(depend_c) == "" or compilation_unit.bytecode_runtime(depend_c) == "":
            # logger.debug(f"依赖合约 {depend_c}的bytecode为空, 已移除")
            logger.debug(f"Dependency contract {depend_c}'s bytecode is empty and has been removed.")
            res.remove(depend_c)

    # logger.info("依赖合约为: " + str(res) + ", 总共有: " + str(len(sl.contracts)) + "个合约, 需要部署的合约有: " + str(
        logger.info("Dependent contracts: " + str(res) + ", total contracts: " + str(len(sl.contracts)) + ", contracts to deploy: " + str(len(res)))
    return list(res), sl


def analysis_main_contract_constructor(file_path: str, _contract_name: str, sl: Slither = None):
    """
    Phân tích hàm khởi tạo của hợp đồng chính.
    Hàm này sử dụng Slither để phân tích hàm khởi tạo của một hợp đồng Solidity, xác định các tham số của nó và theo dõi luồng dữ liệu bên trong hàm khởi tạo nhằm xác định các biến trạng thái được gán giá trị từ các tham số.
    
    Tham số:
        - file_path (str): Đường dẫn đến tệp Solidity cần phân tích.
        - _contract_name (str): Tên của hợp đồng cần phân tích.
        - sl (Slither, tùy chọn): Một instance của Slither. Nếu không được cung cấp, Slither sẽ được khởi tạo mới với `file_path` và `SOLC_BIN_PATH`.
   
    Trả về:
        list: Danh sách các tham số của hàm khởi tạo cùng với loại và giá trị dự kiến của chúng. Nếu hợp đồng không có hàm khởi tạo, trả về danh sách rỗng.
    """
    
    if sl is None:
        sl = Slither(file_path, solc=SOLC_BIN_PATH)
    contract = sl.get_contract_from_name(_contract_name)
    # assert len(contract) == 1, "理论上, 根据合约名字, 只能找到一个合约"
    assert len(contract) == 1, "In theory, there should only be one contract based on the contract name"

    contract = contract[0]
    # 1. Analyze the constructor of the contract
    constructor = contract.constructor
    if constructor is None:  # No constructor
        return []
    # 1. Obtain all parameters of the constructor. If the name is not "address", set it to YA_DO_NOT_KNOW.
    # For other types, initialize it as a list to store data flow.

    res = []
    for p in constructor.parameters:
        if (hasattr(p.type, "type") and hasattr(p.type.type, "kind") and p.type.type.kind == "contract"):
            res.append((p.name, "contract", p.name, [p.type.type.name]))
        elif hasattr(p.type, "name"):
            if p.type.name != "address":
                res.append((p.name, p.type.name, "YA_DO_NOT_KNOW", ["YA_DO_NOT_KNOW"]))
            else:
                res.append((p.name, p.type.name, [p.name], []))
        else:  # Might be an array
            return None
    # 2. Analyze data flow inside the constructor
    for exps in constructor.expressions:  # Parse expressions inside the constructor, analyzing variables assigned from parameters
        if isinstance(exps, AssignmentOperation):
            exps_right = exps.expression_right
            exps_left = exps.expression_left
            if isinstance(exps_right, Identifier) and isinstance(exps_left, Identifier):
                for cst_param in res:
                    if isinstance(cst_param[2], list) and exps_right.value.name in cst_param[2]:
                        cst_param[2].append(exps_left.value.name)
            elif isinstance(exps_right, TypeConversion) and isinstance(exps_left, Identifier):
                param_name, param_map_contract_name = extract_param_contract_map(exps_right)
                if param_name is not None and param_map_contract_name is not None:
                    for cst_param in res:
                        if isinstance(cst_param[2], list) and param_name in cst_param[2]:
                            cst_param[3].append(param_map_contract_name)
        elif isinstance(exps, TypeConversion):
            param_name, param_map_contract_name = extract_param_contract_map(exps)
            if param_name is not None and param_map_contract_name is not None:
                for cst_param in res:
                    if isinstance(cst_param[2], list) and param_name in cst_param[2]:
                        cst_param[3].append(param_map_contract_name)
    # Transform res
    ret = []
    for p_name, p_type, _, p_value in res:
        if p_type == "address" and len(p_value) == 0:
            p_value = ["YA_DO_NOT_KNOW"]
        p_value = list(set(p_value))
        # assert len(p_value) == 1, "理论上, 每个参数只能有一个预期值"
        assert len(p_value) == 1, "In theory, each parameter can only have one expected value"
        ret.append(f"{p_name} {p_type} {p_value[0]}")
    # logger.debug("构造函数参数为: " + str(ret))
    logger.debug("Constructor parameters: " + str(ret)) # Constructor parameters
    return ret


def extract_param_contract_map(exps: TypeConversion):
    """
    Trích xuất thông tin về tham số và contract từ một biểu thức chuyển đổi kiểu (TypeConversion).
    Args:
        exps (TypeConversion): Đối tượng biểu thức chuyển đổi kiểu cần được phân tích.
    
    Returns:
        tuple: Trả về một tuple gồm hai phần tử:
        - Phần tử thứ nhất: Tên của tham số (str hoặc None)
        - Phần tử thứ hai: Tên của contract (str hoặc None)
        Nếu không thể trích xuất được thông tin, cả hai giá trị đều là None.
    
    Chi tiết:
        Hàm kiểm tra xem biểu thức đầu vào có phải là một identifier được chuyển đổi thành
        một kiểu contract hay không. Nếu thỏa mãn điều kiện, hàm sẽ trả về tên của tham số
        và tên của contract tương ứng.
    """
    
    inner_exp = exps.expression
    if isinstance(inner_exp, Identifier) \
            and isinstance(exps.type, UserDefinedType) \
            and hasattr(exps.type, "type") \
            and isinstance(exps.type.type, Contract):
        return inner_exp.value.name, exps.type.type.name
    else:
        return None, None
