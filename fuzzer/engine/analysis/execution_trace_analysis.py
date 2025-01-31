#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import random
import time
import json
import psutil

from fuzzer.engine.environment import FuzzingEnvironment
from fuzzer.engine.plugin_interfaces import OnTheFlyAnalysis

from fuzzer.utils.utils import initialize_logger, convert_stack_value_to_int, convert_stack_value_to_hex, \
    normalize_32_byte_hex_address, get_function_signature_mapping
from eth._utils.address import force_bytes_to_address
from eth_utils import to_hex, to_int, int_to_big_endian, encode_hex, ValidationError, to_canonical_address, \
    to_normalized_address

from z3 import simplify, BitVec, BitVecVal, Not, Optimize, sat, unsat, unknown, is_expr
from z3.z3util import get_vars

from fuzzer.utils import settings
import json


'''
Đây là một script Python dùng để thực hiện phân tích và kiểm thử hợp đồng thông minh, cụ thể là
thông qua việc thực hiện symbolic execution và phân tích các điều kiện logic trong hợp đồng. 
Chương trình có thể nhận đầu vào là mã nguồn hợp đồng thông minh, sau đó tiến hành kiểm tra 
các điều kiện tiềm ẩn và các lỗi bảo mật có thể xảy ra trong quá trình thực thi hợp đồng.
'''



class ExecutionTraceAnalyzer(OnTheFlyAnalysis):
    def __init__(self, fuzzing_environment: FuzzingEnvironment): #Hàm khởi tạo lớp Execution Trace Analyzer 
        '''
        Khởi tạo logger cho phân tích.
        Thiết lập môi trường fuzzing để theo dõi và ghi lại các kết quả.
        '''
        self.logger = initialize_logger("Analysis")
        self.env = fuzzing_environment
        self.symbolic_execution_count = 0

    def setup(self, ng, engine):
        pass

    def execute(self, population, engine): #Hàm thực thi phân tích
        '''
        Xóa dữ liệu bộ nhớ cũ.
        Hàm thực thi phân tích, thực hiện thực thi từng cá thể trong quần thể 
        Cập nhật các thống kê sau khi thực hiện kiểm thử.
        '''
        self.env.memoized_fitness.clear()
        self.env.memoized_storage.clear()
        self.env.memoized_symbolic_execution.clear()
        self.env.individual_branches.clear()

        executed_individuals = dict()
        for i, individual in enumerate(population.individuals):
            if individual.hash in executed_individuals:
                population.individuals[i] = executed_individuals[individual.hash]
                continue
            self.execution_function(individual, self.env)
            executed_individuals[individual.hash] = individual
        executed_individuals.clear()

        # Update statistic variables.
        engine._update_statvars()

    def register_step(self, g, population, engine): #Hàm đăng ký bước thực thi
        '''
        Hàm này được gọi mỗi bước trong quá trình fuzzing để thực hiện 
        kiểm thử và ghi lại các thống kê, bao gồm tỷ lệ phủ mã và phủ nhánh.
        '''
        self.execute(population, engine)

        code_coverage_percentage = 0
        if len(self.env.overall_pcs) > 0:
            code_coverage_percentage = (len(self.env.code_coverage) / len(self.env.overall_pcs)) * 100

        branch_coverage = 0
        for pc in self.env.visited_branches:
            branch_coverage += len(self.env.visited_branches[pc])
        branch_coverage_percentage = 0
        if len(self.env.overall_jumpis) > 0:
            branch_coverage_percentage = (branch_coverage / (len(self.env.overall_jumpis) * 2)) * 100

        msg = 'Generation number {} \t Code coverage: {:.2f}% ({}/{}) \t Branch coverage: {:.2f}% ({}/{}) \t ' \
              'Transactions: {} ({} unique, {} from cross)   \t Time: {}'.format(
            g + 1, code_coverage_percentage, len(self.env.code_coverage), len(self.env.overall_pcs),
            branch_coverage_percentage, branch_coverage, len(self.env.overall_jumpis) * 2, self.env.nr_of_transactions,
            len(self.env.unique_individuals), settings.CROSS_TRANS_EXEC_COUNT,
            time.time() - self.env.execution_begin)
        self.logger.title(msg)

        # Save to results
        if "generations" not in self.env.results:
            self.env.results["generations"] = []

        self.env.results["generations"].append({
            "generation": g + 1,
            "time": time.time() - self.env.execution_begin,
            "total_transactions": self.env.nr_of_transactions,
            "unique_transactions": len(self.env.unique_individuals),
            "code_coverage": code_coverage_percentage,
            "branch_coverage": branch_coverage_percentage,
            "cross_transactions": settings.CROSS_TRANS_EXEC_COUNT
        })

        if len(self.env.code_coverage) == self.env.previous_code_coverage_length:  # Nếu không có thay đổi trong độ phủ mã 
            self.symbolic_execution(population.indv_generator, population.other_generators)
            if self.symbolic_execution_count == settings.MAX_SYMBOLIC_EXECUTION:
                del population.individuals[:]
                population.init(no_cross=True)
                self.logger.debug("Resetting population...")
                self.execute(population, engine)
                self.symbolic_execution_count = 0
            self.symbolic_execution_count += 1
        else:
            self.symbolic_execution_count = 0

        self.env.previous_code_coverage_length = len(self.env.code_coverage)

    def execution_function(self, indv, env: FuzzingEnvironment):
        env.unique_individuals.add(indv.hash)

        # Initialize metric (Thiết lập các chỉ số đánh giá)
        branches = {}
        indv.data_dependencies = []
        contract_address = None

        env.detector_executor.initialize_detectors()

        for transaction_index, test in enumerate(indv.solution):

            this_error_cross_check = True

            transaction = test["transaction"]

            _function_hash = transaction["data"][:10] if transaction["data"].startswith("0x") else transaction["data"][
                                                                                                   :8]
            _function_hash = "fallback" if _function_hash == '' else _function_hash
            _array_size_indexes = dict()

            if transaction["to"] is None and contract_address is not None:
                transaction["to"] = contract_address

            if transaction["to"] is None:
                continue

            try:
                result = env.instrumented_evm.deploy_transaction(test)  # Thực thi giao dịch
            except ValidationError as e:
                self.logger.error("Validation error in %s : %s (ignoring for now)", indv.hash, e)
                continue

            if not result.is_error and transaction["to"] == b'':
                contract_address = encode_hex(result.msg.storage_address)
                self.logger.debug("(%s - %d) Contract deployed at %s", indv.hash, transaction_index, contract_address)

            for child_computation in result.children:
                if child_computation.msg.to not in env.other_contracts:
                    continue
                if child_computation.msg.to not in env.children_code_coverage:
                    env.children_code_coverage[child_computation.msg.to] = set()
                env.children_code_coverage[child_computation.msg.to].update([x["pc"] for x in child_computation.trace])

            env.nr_of_transactions += 1

            previous_instruction = None
            previous_branch = []
            previous_branch_expression = None
            previous_branch_address = None
            previous_call_address = None
            sha3 = {}

            for i, instruction in enumerate(result.trace):
                if settings.MAIN_CONTRACT_NAME != "" and settings.TRANS_INFO[settings.MAIN_CONTRACT_NAME] != \
                        test["transaction"]["to"]:
                    #Đối với các tình huống liên quan đến hợp đồng chéo, tạm thời không thống kê các hợp đồng khác
                    continue

                env.symbolic_taint_analyzer.propagate_taint(instruction, contract_address)

                env.detector_executor.run_detectors(previous_instruction, instruction, env.results["errors"],
                                                    env.symbolic_taint_analyzer.get_tainted_record(index=-2), indv, env,
                                                    previous_branch,
                                                    transaction_index)

                #trong trường hợp xử lý constructor (hàm khởi tạo), không cần phải quan tâm đến 
                # các chi tiết cụ thể như đầu vào của constructor, độ phủ mã, hoặc các dấu vết thực thi, 
                # vì chúng không liên quan trực tiếp đến mã đã triển khai hoặc mã đang phân tích.
                if indv.chromosome[transaction_index]["arguments"][0] == "constructor":
                    continue


                # Độ phủ mã (code coverage), xác định xem trace có thuộc về hợp đồng chính hay không. 
                # Nếu không thuộc về hợp đồng chính, thì không thêm vào code_coverage. 
                
                env.code_coverage.add(hex(instruction["pc"]))

                # Dynamically build control flow graph
                if env.cfg:
                    env.cfg.execute(instruction["pc"], instruction["stack"], instruction["op"], env.visited_branches,
                                    env.results["errors"].keys())
                # thực thi lệnh và cập nhật thông tin trong đồ thị luồng điều khiển (CFG). Cụ thể, nó ghi nhận 
                # các chỉ số chương trình (PC), các giá trị trong ngăn xếp và các nhánh đã đi qua.    
                    

                if previous_instruction and previous_instruction["op"] == "SHA3":
                    sha3[instruction["stack"][-1][1]] = instruction["memory"]

                elif previous_instruction and previous_instruction["op"] == "ADD":
                    if previous_instruction["stack"][-1][1] in sha3:
                        sha3[instruction["stack"][-1][1]] = sha3[previous_instruction["stack"][-1][1]]
                    if previous_instruction["stack"][-2][1] in sha3:
                        sha3[instruction["stack"][-1][1]] = sha3[previous_instruction["stack"][-2][1]]

                if instruction["op"] == "JUMPI":
                    jumpi_pc = hex(instruction["pc"])
                    if jumpi_pc not in env.visited_branches:
                        env.visited_branches[jumpi_pc] = {}
                    if jumpi_pc not in branches:
                        branches[jumpi_pc] = dict()

                    destination = convert_stack_value_to_int(instruction["stack"][-1])
                    jumpi_condition = convert_stack_value_to_int(instruction["stack"][-2])

                    if jumpi_condition == 0:
                        # Không nhảy, nhưng tăng chỉ số chương trình (PC)
                        branches[jumpi_pc][hex(destination)] = False
                        branches[jumpi_pc][hex(instruction["pc"] + 1)] = True
                    else:
                        # Nhảy đến địa chỉ chỉ định
                        branches[jumpi_pc][hex(destination)] = True
                        branches[jumpi_pc][hex(instruction["pc"] + 1)] = False

                    env.visited_branches[jumpi_pc][jumpi_condition] = {}
                    env.visited_branches[jumpi_pc][jumpi_condition]["indv_hash"] = indv.hash
                    env.visited_branches[jumpi_pc][jumpi_condition]["chromosome"] = indv.chromosome
                    env.visited_branches[jumpi_pc][jumpi_condition]["transaction_index"] = transaction_index

                    tainted_record = env.symbolic_taint_analyzer.check_taint(instruction=instruction)
                    if tainted_record and tainted_record.stack and tainted_record.stack[-2]:
                        if jumpi_condition != 0:
                            previous_branch.append(tainted_record.stack[-2][0] != 0)
                        else:
                            previous_branch.append(tainted_record.stack[-2][0] == 0)
                        previous_branch_expression = previous_branch[-1]
                        env.visited_branches[jumpi_pc][jumpi_condition]["expression"] = previous_branch.copy()
                    else:
                        env.visited_branches[jumpi_pc][jumpi_condition]["expression"] = None
                        previous_branch_expression = None

                    previous_branch_address = jumpi_pc

                # Extract data dependencies (read-after-write)
                elif instruction["op"] == "SLOAD":
                    if instruction["stack"][-1][1] in sha3:
                        hash = instruction["stack"][-1][1]
                        while hash in sha3:
                            if len(sha3[hash]) == 64:
                                hash = sha3[hash][32:64]
                            else:
                                hash = sha3[hash]
                        storage_slot = int.from_bytes(hash, byteorder='big')
                    else:
                        storage_slot = convert_stack_value_to_int(instruction["stack"][-1])

                    _function_hash = indv.chromosome[transaction_index]["arguments"][0]
                    if _function_hash not in self.env.data_dependencies:
                        self.env.data_dependencies[_function_hash] = {"read": set(), "write": set()}
                    self.env.data_dependencies[_function_hash]["read"].add(storage_slot)
                    temp_dict = settings.GLOBAL_DATA_INFO.get(indv.hash, {})
                    temp_dict_2 = temp_dict.get(transaction_index, {})
                    temp_dict_3 = temp_dict_2.get("read", set())
                    temp_dict_3.add(storage_slot)
                    temp_dict_2["read"] = temp_dict_3
                    temp_dict[transaction_index] = temp_dict_2
                    settings.GLOBAL_DATA_INFO[indv.hash] = temp_dict


                elif instruction["op"] == "SSTORE":
                    if instruction["stack"][-1][1] in sha3:
                        hash = instruction["stack"][-1][1]
                        while hash in sha3:
                            if len(sha3[hash]) == 64:
                                hash = sha3[hash][32:64]
                            else:
                                hash = sha3[hash]
                        storage_slot = int.from_bytes(hash, byteorder='big')
                    else:
                        storage_slot = convert_stack_value_to_int(instruction["stack"][-1])

                    _function_hash = indv.chromosome[transaction_index]["arguments"][0]
                    if _function_hash not in self.env.data_dependencies:
                        self.env.data_dependencies[_function_hash] = {"read": set(), "write": set()}
                    self.env.data_dependencies[_function_hash]["write"].add(storage_slot)
                    temp_dict = settings.GLOBAL_DATA_INFO.get(indv.hash, {})
                    temp_dict_2 = temp_dict.get(transaction_index, {})
                    temp_dict_3 = temp_dict_2.get("write", set())
                    temp_dict_3.add(storage_slot)
                    temp_dict_2["write"] = temp_dict_3
                    temp_dict[transaction_index] = temp_dict_2
                    settings.GLOBAL_DATA_INFO[indv.hash] = temp_dict


                # If something goes wrong, we need to clean some pools
                elif instruction["op"] in ["REVERT", "INVALID", "ASSERTFAIL"]:
                    # Nếu gặp phải lỗi trong quá trình thực thi như REVERT, INVALID hoặc ASSERTFAIL, 
                    # hệ thống sẽ kiểm tra điều kiện lỗi và có thể kích hoạt cơ chế kiểm tra chéo
                    # (cross-check) hoặc khôi phục các tham số.
                    if this_error_cross_check and settings.TRANS_COMP_OPEN and random.randint(0,
                                                                                              100) <= settings.P_OPEN_CROSS:
                        hash_4_chromosome = count_hash_4_chromosome(indv.chromosome)
                        if hash_4_chromosome not in settings.TRANS_CROSS_BAD_INDVS_HASH:
                            settings.TRANS_MODE = "cross"  # 启动交叉模式
                            indv_success = (
                                indv,
                                transaction_index)  
                                # Tất cả các giao dịch từ 0 đến transaction_index-1 đã thực thi thành công, và giao dịch tại transaction_index đã thất bại
                            settings.TRANS_CROSS_BAD_INDVS.append(indv_success)
                            settings.TRANS_CROSS_BAD_INDVS_HASH.add(hash_4_chromosome)
                            this_error_cross_check = False
                    if previous_branch_expression is not None and is_expr(previous_branch_expression):
                        # Only remove from pool when you are sure which variable caused the exception
                        if len(get_vars(previous_branch_expression)) == 1:
                            for var in get_vars(previous_branch_expression):
                                _str_var = str(var)
                                if _str_var.startswith("calldataload_") or str(var).startswith("calldatacopy_"):
                                    _parameter_index = int(str(var).split("_")[-1])
                                    _transaction_index = int(str(var).split("_")[-2])
                                    _function_hash = indv.chromosome[_transaction_index]["arguments"][0]
                                    _argument = indv.chromosome[_transaction_index]["arguments"][_parameter_index + 1]
                                    indv.generator.remove_argument_from_pool(_function_hash, _parameter_index,
                                                                             _argument)

                                elif _str_var.startswith("callvalue_"):
                                    _function_hash = indv.chromosome[transaction_index]["arguments"][0]
                                    _amount = transaction["value"]
                                    if _amount == 0 or _amount == 1:
                                        indv.generator.remove_amount_from_pool(_function_hash, _amount)

                                elif _str_var.startswith("caller_"):
                                    _function_hash = indv.chromosome[transaction_index]["arguments"][0]
                                    _caller = transaction["from"]
                                    indv.generator.remove_account_from_pool(_function_hash, _caller)

                                elif _str_var.startswith("gas_"):
                                    _function_hash = indv.chromosome[transaction_index]["arguments"][0]
                                    _gas_limit = indv.chromosome[transaction_index]["gaslimit"]
                                    indv.generator.remove_gaslimit_from_pool(_function_hash, _gas_limit)

                                elif _str_var.startswith("blocknumber_"):
                                    _function_hash = indv.chromosome[transaction_index]["arguments"][0]
                                    _blocknumber = indv.chromosome[transaction_index]["blocknumber"]
                                    indv.generator.remove_blocknumber_from_pool(_function_hash, _blocknumber)

                                elif _str_var.startswith("timestamp_"):
                                    _function_hash = indv.chromosome[transaction_index]["arguments"][0]
                                    _timestamp = indv.chromosome[transaction_index]["timestamp"]
                                    indv.generator.remove_timestamp_from_pool(_function_hash, _timestamp)

                                elif _str_var.startswith("call_"):
                                    _function_hash = indv.chromosome[transaction_index]["arguments"][0]
                                    _var_split = str(var).split("_")
                                    _address = to_normalized_address(_var_split[2])
                                    _result = int(_var_split[3], 16)
                                    indv.generator.remove_callresult_from_pool(_function_hash, _address, _result)

                                elif _str_var.startswith("extcodesize"):
                                    _function_hash = indv.chromosome[transaction_index]["arguments"][0]
                                    _var_split = str(var).split("_")
                                    _address = to_normalized_address(_var_split[2])
                                    _size = int(_var_split[3], 16)
                                    indv.generator.remove_extcodesize_from_pool(_function_hash, _address, _size)
                                elif _str_var.startswith("returndatasize"):
                                    _function_hash = indv.chromosome[transaction_index]["arguments"][0]
                                    _var_split = str(var).split("_")
                                    _address = to_normalized_address(_var_split[2])
                                    _size = int(_var_split[3], 16)
                                    indv.generator.remove_returndatasize_from_pool(_function_hash, _address, _size)

                
                # Trong quá trình phân tích, các biến có thể bị nhiễm bẩn (tainted) khi có thao tác mà tác động đến chúng.
                # Các biến này sẽ được ghi lại trong bảng tạm thời để theo dõi 
                elif instruction["op"] == "BALANCE":
                    taint = BitVec("_".join(["balance", str(transaction_index)]), 256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                elif instruction["op"] in ["CALL", "STATICCALL"]:
                    _address_as_hex = to_hex(force_bytes_to_address(
                        int_to_big_endian(convert_stack_value_to_int(result.trace[i]["stack"][-2]))))
                    if i + 1 < len(result.trace):
                        _result_as_hex = convert_stack_value_to_hex(result.trace[i + 1]["stack"][-1])
                    else:
                        _result_as_hex = ""
                    previous_call_address = _address_as_hex
                    call_type = "call"
                    if instruction["op"] == "STATICCALL":
                        call_type = "staticcall"
                    taint = BitVec("_".join(
                        [call_type, str(transaction_index), str(_address_as_hex), str(_result_as_hex),
                         str(instruction["pc"])]), 256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                elif instruction["op"] == "CALLER":
                    taint = BitVec("_".join(["caller", str(transaction_index)]), 256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                elif instruction["op"] == "CALLDATALOAD":
                    input_index = convert_stack_value_to_int(instruction["stack"][-1])
                    if input_index > 0 and _function_hash in env.interface:
                        input_index = int((input_index - 4) / 32)
                        if input_index < len(env.interface[_function_hash]):
                            parameter_type = env.interface[_function_hash][input_index]
                            if '[' in parameter_type:
                                array_size_index = convert_stack_value_to_int(result.trace[i + 1]["stack"][-1]) / 32
                                _array_size_indexes[array_size_index] = input_index
                            elif "bytes" in parameter_type:
                                pass
                            else:
                                taint = BitVec("_".join(["calldataload",
                                                         str(transaction_index),
                                                         str(input_index)
                                                         ]), 256)
                                env.symbolic_taint_analyzer.introduce_taint(taint, instruction)
                        else:
                            if input_index in _array_size_indexes:
                                array_size = convert_stack_value_to_int(result.trace[i + 1]["stack"][-1])
                                taint = BitVec("_".join(["inputarraysize",
                                                         str(transaction_index),
                                                         str(_array_size_indexes[input_index])
                                                         ]), 256)
                                env.symbolic_taint_analyzer.introduce_taint(taint, instruction)
                            else:
                                pass

                elif instruction["op"] == "CALLDATACOPY":
                    destOffset = convert_stack_value_to_int(instruction["stack"][-1])
                    offset = convert_stack_value_to_int(instruction["stack"][-2])
                    array_start_index = (offset - 4) / 32
                    lenght = convert_stack_value_to_int(instruction["stack"][-3])

                    if array_start_index - 1 in _array_size_indexes:
                        taint = BitVec("_".join(["calldatacopy",
                                                 str(transaction_index),
                                                 str(_array_size_indexes[array_start_index - 1])
                                                 ]), 256)
                        env.symbolic_taint_analyzer.introduce_taint(taint, instruction)
                    else:
                        pass

                elif instruction["op"] == "CALLDATASIZE":
                    taint = BitVec("_".join(["calldatasize", str(transaction_index)]), 256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                elif instruction["op"] == "CALLVALUE":
                    taint = BitVec("_".join(["callvalue", str(transaction_index)]), 256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                elif instruction["op"] == "GAS":
                    taint = BitVec("_".join(["gas", str(transaction_index)]), 256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                # BLOCK Opcodes
                elif instruction["op"] == "BLOCKHASH":
                    taint = BitVec("_".join(["blockhash", str(transaction_index)]), 256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                elif instruction["op"] == "COINBASE":
                    taint = BitVec("_".join(["coinbase", str(transaction_index)]), 256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                elif instruction["op"] == "TIMESTAMP":
                    taint = BitVec("_".join(["timestamp", str(transaction_index)]), 256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                elif instruction["op"] == "NUMBER":
                    taint = BitVec("_".join(["blocknumber", str(transaction_index)]), 256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                elif instruction["op"] == "DIFFICULTY":
                    taint = BitVec("_".join(["difficulty", str(transaction_index)]), 256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                elif instruction["op"] == "GASLIMIT":
                    taint = BitVec("_".join(["gaslimit", str(transaction_index)]), 256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                elif instruction["op"] == "EXTCODESIZE":
                    _address_as_hex = to_hex(
                        force_bytes_to_address(
                            int_to_big_endian(convert_stack_value_to_int(result.trace[i]["stack"][-1]))))
                    if i + 1 < len(result.trace):
                        _result_as_hex = convert_stack_value_to_hex(result.trace[i + 1]["stack"][-1])
                    else:
                        _result_as_hex = ""
                    taint = BitVec(
                        "_".join(["extcodesize", str(transaction_index), str(_address_as_hex), str(_result_as_hex)]),
                        256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                elif instruction["op"] == "RETURNDATASIZE":
                    if previous_call_address:
                        if i + 1 < len(result.trace):
                            _size = convert_stack_value_to_int(result.trace[i + 1]["stack"][-1])
                        else:
                            _size = 0
                        taint = BitVec(
                            "_".join(["returndatasize", str(transaction_index), previous_call_address, str(_size)]),
                            256)
                        env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                previous_instruction = instruction

            env.symbolic_taint_analyzer.clear_callstack()

            if not result.is_error and not transaction["to"]:
                contract_address = encode_hex(result.msg.storage_address)

        env.individual_branches[indv.hash] = branches

        env.symbolic_taint_analyzer.clear_storage()
        env.instrumented_evm.restore_from_snapshot()

    def get_coverage_with_children(self, children_code_coverage, code_coverage):
        code_coverage = len(code_coverage)

        for child_cc in children_code_coverage:
            code_coverage += len(child_cc)
        return code_coverage

    def symbolic_execution(self, indv_generator, other_generators):
        if not self.env.args.constraint_solving:  # Có bật chế độ thực thi ký hiệu (symbolic execution) không
            return

        for index, pc in enumerate(self.env.visited_branches):
            self.logger.debug("b(%d) pc : %s - visited branches : %s", index, pc, self.env.visited_branches[pc].keys())

            if len(self.env.visited_branches[pc]) != 1:  # Nếu nhánh này đã có 2 đường đi có thể xuất phát, thì bỏ qua, không cần phải tạo thêm nhánh cho nó.
                continue

            branch, _d = next(iter(self.env.visited_branches[pc].items()))

            if not _d["expression"]:
                self.logger.debug("No expression for b(%d) pc : %s", index, pc)
                continue

            negated_branch = simplify(Not(_d["expression"][-1]))  # Lật ngược điều kiện cuối cùng

            if negated_branch in self.env.memoized_symbolic_execution:
                continue

            self.env.solver.reset()
            for expression_index in range(len(_d["expression"]) - 1):  # Thêm tất cả các điều kiện ngoại trừ điều kiện cuối cùng vào bộ giải quyết ràng buộc
                expression = simplify(_d["expression"][expression_index])
                self.env.solver.add(expression)
            self.env.solver.add(negated_branch)  # Thêm điều kiện đã bị đảo ngược vào bộ giải quyết ràng buộc

            check = self.env.solver.check()  # Kiểm tra xem có thỏa mãn không, nếu có nghĩa là điều kiện đảo ngược có thể thỏa mãn
                                            # trong bộ giải quyết ràng buộc, tồn tại một giá trị cho phép nhánh kia thành công, nhưng! Không chắc chắn thỏa mãn trong thực tế

            if check == sat:
                model = self.env.solver.model()

                self.logger.debug("(%s) Symbolic Solution to branch %s: %s ", _d["indv_hash"], pc, 
                                  "; ".join([str(x) + " (" + str(model[x]) + ")" for x in model]))  

                for variable in model:
                    if str(variable).startswith("underflow"):
                        continue

                    var_split = str(variable).split("_")
                    transaction_index = int(var_split[1])

                    if str(variable).startswith("balance"):
                        _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                        opt = Optimize()
                        for expression_index in range(len(_d["expression"]) - 1):
                            opt.add(_d["expression"][expression_index])
                        opt.add(negated_branch)
                        check = opt.check()
                        if check == sat:
                            opt_model = opt.model()
                            balance = int(opt_model[variable].as_long())
                            if _d["chromosome"][transaction_index]["contract"]:
                                indv_generator.add_balance_to_pool(_function_hash,
                                                                   self.env.instrumented_evm.get_balance(
                                                                       to_canonical_address(
                                                                           _d["chromosome"][transaction_index][
                                                                               "contract"])))
                            indv_generator.add_balance_to_pool(_function_hash, balance)

                    elif str(variable).startswith("blocknumber"):
                        _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                        blocknumber = int(model[variable].as_long())
                        indv_generator.add_blocknumber_to_pool(_function_hash,
                                                               self.env.instrumented_evm.vm.state.block_number)
                        indv_generator.add_blocknumber_to_pool(_function_hash, blocknumber)

                    elif str(variable).startswith("call_") or str(variable).startswith("staticcall_"):
                        address = to_normalized_address(var_split[2])
                        old_result = int(var_split[3], 16)
                        _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                        new_result = 1 - old_result
                        # indv_generator.add_callresult_to_pool(_function_hash, address, old_result)
                        # indv_generator.add_callresult_to_pool(_function_hash, address, new_result)

                    elif str(variable).startswith("caller_"):
                        _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                        if model[variable].as_long() > 8 and model[variable].as_long() < 2 ** 160:
                            account_address = normalize_32_byte_hex_address(
                                "0x" + hex(model[variable].as_long()).replace("0x", "").zfill(40))
                            if not self.env.instrumented_evm.has_account(account_address):
                                self.env.instrumented_evm.restore_from_snapshot()
                                self.env.instrumented_evm.accounts.append(
                                    self.env.instrumented_evm.create_fake_account(account_address))
                                self.env.instrumented_evm.create_snapshot()
                            indv_generator.add_account_to_pool(_function_hash,
                                                               _d["chromosome"][transaction_index]["account"])
                            indv_generator.add_account_to_pool(_function_hash, account_address)

                    elif str(variable).startswith("calldatacopy_"):
                        _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                        parameter_index = int(var_split[2])
                        if "[" in indv_generator.interface[_function_hash][parameter_index]:
                            if indv_generator.interface[_function_hash][parameter_index].startswith("int"):
                                argument = model[variable].as_signed_long()
                            elif indv_generator.interface[_function_hash][parameter_index].startswith("address"):
                                try:
                                    _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                                    argument = normalize_32_byte_hex_address(hex(model[variable].as_long()))
                                    if not self.env.instrumented_evm.has_account(argument):
                                        self.env.instrumented_evm.restore_from_snapshot()
                                        self.env.instrumented_evm.accounts.append(
                                            self.env.instrumented_evm.create_fake_account(argument))
                                        self.env.instrumented_evm.create_snapshot()
                                except Exception as e:
                                    self.logger.error("(%s) [symbolic execution : calldatacopy ] %s", _function_hash,
                                                      e)
                                    continue
                            else:
                                argument = model[variable].as_long()
                            indv_generator.add_argument_to_pool(_function_hash, parameter_index,
                                                                _d["chromosome"][transaction_index]["arguments"][
                                                                    parameter_index + 1])
                            indv_generator.add_argument_to_pool(_function_hash, parameter_index, argument)

                    elif str(variable).startswith("calldataload_"):
                        _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                        parameter_index = int(var_split[2])
                        # TODO: THE SOLVER DOES NOT CONSIDER THE MAX SIZE OF THE VARIABLE
                        #   GENERATING LATER A eth_abi.exceptions.ValueOutOfBounds
                        if "[" in indv_generator.interface[_function_hash][parameter_index]:  # kiểm tra kiểu dữ liệu xem có phải mảng không
                            if indv_generator.interface[_function_hash][parameter_index].startswith("int"):
                                argument = model[variable].as_signed_long()
                            elif indv_generator.interface[_function_hash][parameter_index].startswith("address"):
                                try:
                                    _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                                    argument = normalize_32_byte_hex_address(hex(model[variable].as_long()))
                                    if not self.env.instrumented_evm.has_account(argument):
                                        self.env.instrumented_evm.restore_from_snapshot()
                                        self.env.instrumented_evm.accounts.append(
                                            self.env.instrumented_evm.create_fake_account(argument))
                                        self.env.instrumented_evm.create_snapshot()
                                except Exception as e:
                                    self.logger.error("(%s) [symbolic execution : calldataload ] %s", _function_hash, e)
                                    continue

                        elif indv_generator.interface[_function_hash][parameter_index].startswith("int"):
                            argument = model[variable].as_signed_long()

                        elif indv_generator.interface[_function_hash][parameter_index] == "address":
                            try:
                                _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                                argument = to_hex(
                                    force_bytes_to_address(int_to_big_endian(int(model[variable].as_long()))))
                                if not self.env.instrumented_evm.has_account(argument):
                                    self.env.instrumented_evm.restore_from_snapshot()
                                    self.env.instrumented_evm.accounts.append(
                                        self.env.instrumented_evm.create_fake_account(argument))
                                    self.env.instrumented_evm.create_snapshot()
                            except Exception as e:
                                self.logger.error("(%s) [symbolic execution : calldataload ] %s", _function_hash, e)
                                continue

                        elif indv_generator.interface[_function_hash][parameter_index] == "string":
                            argument = _d["chromosome"][transaction_index]["arguments"][parameter_index + 1]
                        elif indv_generator.interface[_function_hash][parameter_index].startswith("uint"):
                            argument = model[variable].as_long()
                            bits = 256
                            if indv_generator.interface[_function_hash][parameter_index] != "uint":
                                bits = int(
                                    indv_generator.interface[_function_hash][parameter_index].replace("uint", ""))
                            base = 1 << bits
                            argument %= base
                        else:
                            argument = model[variable].as_long()
                            self.env.solver.add(BitVec(str(variable), 256) != BitVecVal(0, 256))
                            for variable_2 in model:
                                if variable_2 != variable and str(variable_2).startswith("callvalue"):
                                    callvalue_index = int(str(variable_2).split("_")[1])
                                    self.env.solver.add(BitVec(str(variable_2), 256) == BitVecVal(
                                        int(_d["chromosome"][callvalue_index]["amount"]), 256))
                            check = self.env.solver.check()
                            if check == sat:
                                model = self.env.solver.model()
                                argument = model[variable].as_long()

                        indv_generator.add_argument_to_pool(_function_hash, parameter_index,
                                                            _d["chromosome"][transaction_index]["arguments"][
                                                                parameter_index + 1])
                        indv_generator.add_argument_to_pool(_function_hash, parameter_index, argument)

                    elif str(variable).startswith("callvalue_"):
                        _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                        amount = model[variable].as_long()
                        if amount > settings.ACCOUNT_BALANCE:
                            amount = settings.ACCOUNT_BALANCE
                        indv_generator.remove_amount_from_pool(_function_hash, 0)
                        indv_generator.remove_amount_from_pool(_function_hash, 1)
                        indv_generator.add_amount_to_pool(_function_hash, _d["chromosome"][transaction_index]["amount"])
                        indv_generator.add_amount_to_pool(_function_hash, amount)

                    elif str(variable).startswith("gas_"):
                        _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                        indv_generator.add_gaslimit_to_pool(_function_hash,
                                                            _d["chromosome"][transaction_index]["gaslimit"])
                        indv_generator.add_gaslimit_to_pool(_function_hash, model[variable].as_long())

                    elif str(variable).startswith("inputarraysize"):
                        opt = Optimize()
                        for expression_index in range(len(_d["expression"]) - 1):
                            opt.add(_d["expression"][expression_index])
                        opt.add(negated_branch)
                        check = opt.check()
                        if check == sat:
                            opt_model = opt.model()
                            array_size = opt_model[variable].as_long()
                            _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                            parameter_index = int(var_split[2])
                            indv_generator.add_parameter_array_size(_function_hash, parameter_index, len(
                                _d["chromosome"][transaction_index]["arguments"][parameter_index + 1]))
                            indv_generator.add_parameter_array_size(_function_hash, parameter_index, array_size)

                    elif str(variable).startswith("timestamp"):
                        _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                        timestamp = int(model[variable].as_long())
                        indv_generator.add_timestamp_to_pool(_function_hash,
                                                             self.env.instrumented_evm.vm.state.timestamp)
                        indv_generator.add_timestamp_to_pool(_function_hash, timestamp)

                    elif str(variable).startswith("calldatasize"):
                        pass

                    elif str(variable).startswith("extcodesize"):
                        _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                        _address = to_normalized_address(var_split[2])
                        # indv_generator.add_extcodesize_to_pool(_function_hash, _address, int(var_split[3], 16))
                        # indv_generator.add_extcodesize_to_pool(_function_hash, _address, int(model[variable].as_long()))

                    elif str(variable).startswith("returndatasize"):
                        _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                        _address = to_normalized_address(var_split[2])
                        _size = int(var_split[3], 16)
                        # indv_generator.add_returndatasize_to_pool(_function_hash, _address, int(var_split[3], 16))
                        # indv_generator.add_returndatasize_to_pool(_function_hash, _address, int(model[variable].as_long()))

                    else:
                        self.logger.warning("Unknown symbolic variable: %s ", str(variable))

            self.env.memoized_symbolic_execution[negated_branch] = True

    def finalize(self, population, engine): # Hàm này được gọi khi kết thúc quá trình tối ưu hóa
        '''
        Hàm này ghi nhận kết quả của quá trình thực thi, bao gồm số lượng giao dịch, độ bao phủ mã (code coverage), thời gian thực thi, và bộ nhớ tiêu thụ.
        Sau đó, nó lưu các kết quả này vào một tệp JSON nếu có yêu cầu từ tham số đầu vào (self.env.args.results).
        '''
        execution_end = time.time()
        execution_delta = execution_end - self.env.execution_begin

        self.logger.title("-----------------------------------------------------")
        msg = 'Number of generations: \t {}'.format(engine.current_generation + 1)
        self.logger.info(msg)
        msg = 'Number of transactions: \t {} ({} unique)'.format(self.env.nr_of_transactions,
                                                                 len(self.env.unique_individuals))
        self.logger.info(msg)
        msg = 'Transactions per second: \t {:.0f}'.format(self.env.nr_of_transactions / execution_delta)
        self.logger.info(msg)
        code_coverage_percentage = 0
        if len(self.env.overall_pcs) > 0:
            code_coverage_percentage = (len(self.env.code_coverage) / len(self.env.overall_pcs)) * 100
        msg = 'Total code coverage: \t {:.2f}% ({}/{})'.format(code_coverage_percentage,
                                                               len(self.env.code_coverage),
                                                               len(self.env.overall_pcs))
        self.logger.info(msg)
        branch_coverage = 0
        for pc in self.env.visited_branches:
            branch_coverage += len(self.env.visited_branches[pc])
        branch_coverage_percentage = 0
        if len(self.env.overall_jumpis) > 0:
            branch_coverage_percentage = (branch_coverage / (len(self.env.overall_jumpis) * 2)) * 100
        msg = 'Total branch coverage: \t {:.2f}% ({}/{})'.format(branch_coverage_percentage,
                                                                 branch_coverage, len(self.env.overall_jumpis) * 2)
        self.logger.info(msg)
        msg = 'Total execution time: \t {:.2f} seconds'.format(execution_delta)
        self.logger.info(msg)
        msg = 'Total memory consumption: \t {:.2f} MB'.format(
            psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024)
        self.logger.info(msg)

        # Save to results
        self.env.results["transactions"] = {"total": self.env.nr_of_transactions,
                                            "per_second": self.env.nr_of_transactions / execution_delta}
        self.env.results["code_coverage"] = {"percentage": code_coverage_percentage,
                                             "covered": len(self.env.code_coverage),
                                             "total": len(self.env.overall_pcs),
                                             "covered_with_children": self.get_coverage_with_children(
                                                 self.env.children_code_coverage,
                                                 self.env.code_coverage),
                                             "total_with_children": self.env.len_overall_pcs_with_children
                                             }
        self.env.results["branch_coverage"] = {"percentage": branch_coverage_percentage,
                                               "covered": branch_coverage,
                                               "total": len(self.env.overall_jumpis) * 2}
        self.env.results["execution_time"] = execution_delta
        self.env.results["memory_consumption"] = psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024
        self.env.results["address_under_test"] = self.env.population.indv_generator.contract
        self.env.results["seed"] = self.env.seed

        self.env.results["cross_trans_count"] = settings.CROSS_TRANS_EXEC_COUNT

        self.env.results["total_op"] = list(self.env.overall_pcs)
        self.env.results["coverage_op"] = list(self.env.code_coverage)

        # Write results to file
        if self.env.args.results:
            results = {}
            if self.env.args.results.lower().endswith(".json"):
                if os.path.exists(self.env.args.results):
                    with open(self.env.args.results, 'r') as file:
                        results = json.load(file)
                results[self.env.contract_name] = self.env.results
                with open(self.env.args.results, 'w') as file:
                    json.dump(results, file)
            else:
                if os.path.exists(
                        self.env.args.results + '/' + os.path.splitext(os.path.basename(self.env.contract_name))[
                            0] + '.json'):
                    with open(self.env.args.results + '/' + os.path.splitext(os.path.basename(self.env.contract_name))[
                        0] + '.json', 'r') as file:
                        results = json.load(file)
                results[self.env.contract_name] = self.env.results
                with open(self.env.args.results + '/' + os.path.splitext(os.path.basename(self.env.contract_name))[
                    0] + '.json', 'w') as file:
                    json.dump(results, file)

        diff = list(set(self.env.code_coverage).symmetric_difference(set([hex(x) for x in self.env.overall_pcs])))
        self.logger.debug("Instructions not executed: %s", sorted(diff))


def count_hash_4_chromosome(_chromosome: list): # Hàm này được sử dụng để tính toán giá trị hash của một cá thể
    value = 0
    for ch in _chromosome:
        value += hash(ch["account"])
        value += hash(ch["contract"])
        for arg in ch["arguments"]:
            try:
                value += hash(arg)
            except TypeError:
                pass
    return value
