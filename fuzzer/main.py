#!/usr/bin/env python3


# -*- coding: utf-8 -*-

import os
import sys
import time
import json
from datetime import datetime

import solcx
import random
import argparse

from eth_utils import encode_hex, to_canonical_address
from z3 import Solver

from evm import InstrumentedEVM
from detectors import DetectorExecutor
from engine import EvolutionaryFuzzingEngine
from engine.components import Generator, Individual, Population
from engine.analysis import SymbolicTaintAnalyzer
from engine.analysis import ExecutionTraceAnalyzer
from engine.environment import FuzzingEnvironment
from engine.operators import LinearRankingSelection
from engine.operators import DataDependencyLinearRankingSelection
from engine.operators import Crossover
from engine.operators import DataDependencyCrossover
from engine.operators import Mutation
from engine.fitness import fitness_function
from fuzzer.utils.transaction_seq_utils import check_cross_init, gen_trans, init_func

"""
main.py là chính chương trình chính của trình tạo dữ liệu fuzzing cho các hợp đồng thông minh trên Ethereum.
Nó bao gồm các chức năng để khởi tạo môi trường fuzzing, triển khai các hợp đồng phụ thuộc, và chạy quá trình fuzzing
sử dụng các thuật toán di truyền như chọn lọc, lai ghép và đột biến.


    Lớp Fuzzer chịu trách nhiệm quản lý toàn bộ quá trình fuzzing của một hợp đồng thông minh. 
    Nó bao gồm việc triển khai các hợp đồng phụ thuộc, khởi tạo môi trường fuzzing, và chạy công cụ fuzzing.
    

        
        Khởi tạo một đối tượng Fuzzer với các tham số cần thiết như tên hợp đồng, ABI, mã bytecode triển khai và runtime,
        trạng thái blockchain, trình giải thích Z3, các đối số cấu hình, và hạt giống ngẫu nhiên.
        

        
        Triển khai các hợp đồng phụ thuộc được chỉ định trong các đối số cấu hình.
        Nếu triển khai thành công, các hợp đồng này sẽ được thêm vào danh sách tài khoản và môi trường fuzzing sẽ được cập nhật.
        

        
        Chạy quá trình fuzzing chính bằng cách tạo các tài khoản giả, triển khai các hợp đồng phụ thuộc nếu cần,
        khởi tạo quần thể ban đầu, áp dụng các toán tử di truyền, và thực hiện fuzzing trong một số thế hệ đã định.
        

    
    Hàm chính để thực thi chương trình fuzzing. Nó phân tích các đối số dòng lệnh, thiết lập môi trường fuzzing,
    biên dịch mã nguồn nếu cần thiết, và khởi chạy quá trình fuzzing bằng cách tạo một đối tượng Fuzzer và gọi phương thức run().
    

    
    Hàm này xử lý việc phân tích các đối số dòng lệnh được cung cấp bởi người dùng.
    Nó xác định các tham số như tệp nguồn Solidity, ABI, tên hợp đồng, trạng thái blockchain, 
    và các tham số cấu hình cho quá trình fuzzing như số thế hệ, kích thước quần thể, xác suất lai ghép và đột biến.
    Hàm này cũng thực hiện các kiểm tra hợp lệ trên các đối số đã nhập và thiết lập các cài đặt cấu hình tương ứng.
"""




# 获取根目录
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# 将根目录添加到path中
sys.path.append(BASE_DIR)
from fuzzer.utils import settings
from utils.source_map import SourceMap
from utils.utils import initialize_logger, compile, get_interface_from_abi, get_pcs_and_jumpis, \
    get_function_signature_mapping
from utils.control_flow_graph import ControlFlowGraph


class Fuzzer:
    """
    Mô tả lớp Fuzzer:
    Lớp `Fuzzer` chịu trách nhiệm thực hiện quá trình fuzzing cho hợp đồng thông minh. Các chức năng chính bao gồm:
    Attributes:
        contract_name (str): Tên của hợp đồng cần fuzzing.
        abi (dict): ABI của hợp đồng.
        deployment_bytecode (str): Bytecode triển khai của hợp đồng.
        runtime_bytecode (str): Bytecode thời gian chạy của hợp đồng.
        test_instrumented_evm: EVM được trang bị để kiểm thử.
        blockchain_state: Trạng thái hiện tại của blockchain.
        solver: Trình giải để giải quyết các điều kiện trong quá trình fuzzing.
        args: Các đối số cấu hình cho quá trình fuzzing.
        seed (int): Hạt giống để khởi tạo quá trình fuzzing.
        source_map (dict, optional): Bản đồ nguồn cho hợp đồng.
        whole_compile_info (dict, optional): Thông tin biên dịch đầy đủ của hợp đồng.
    Methods:
        __init__(...): Khởi tạo các thuộc tính cần thiết cho quá trình fuzzing và thiết lập môi trường fuzzing.
        deploy_depend_contracts(): Triển khai các hợp đồng phụ thuộc trước khi bắt đầu fuzzing.
        run(): Thực thi quá trình fuzzing, bao gồm triển khai hợp đồng chính, tạo quần thể ban đầu, áp dụng các toán tử di truyền và chạy engine fuzzing.
    Ví dụ sử dụng:
        fuzzer = Fuzzer(contract_name, abi, deployment_bytecode, runtime_bytecode, ...)
        fuzzer.run()
    """
    
    def __init__(self, contract_name, abi, deployment_bytecode, runtime_bytecode, test_instrumented_evm,
                 blockchain_state, solver, args, seed, source_map=None, whole_compile_info=None):
        global logger

        logger = initialize_logger("Fuzzer  ")
        logger.title("Fuzzing contract %s", contract_name)

        cfg = ControlFlowGraph()
        cfg.build(runtime_bytecode, settings.EVM_VERSION)

        self.contract_name = contract_name
        self.interface, self.interface_mapper = get_interface_from_abi(abi)
        self.deployement_bytecode = deployment_bytecode
        self.blockchain_state = blockchain_state
        self.instrumented_evm = test_instrumented_evm
        self.solver = solver
        self.args = args
        # 该合约依赖的其他合约
        self.depend_contracts = args.depend_contracts
        self.whole_compile_info = whole_compile_info

        # Get some overall metric on the code
        self.overall_pcs, self.overall_jumpis = get_pcs_and_jumpis(runtime_bytecode)

        # Initialize results
        self.results = {"errors": {}}

        # Initialize fuzzing environment
        self.env = FuzzingEnvironment(instrumented_evm=self.instrumented_evm,
                                      contract_name=self.contract_name,
                                      solver=self.solver,
                                      results=self.results,
                                      symbolic_taint_analyzer=SymbolicTaintAnalyzer(),
                                      detector_executor=DetectorExecutor(source_map,
                                                                         get_function_signature_mapping(abi)),
                                      interface=self.interface,
                                      overall_pcs=self.overall_pcs,
                                      overall_jumpis=self.overall_jumpis,
                                      len_overall_pcs_with_children=0,
                                      other_contracts=list(),
                                      args=args,
                                      seed=seed,
                                      cfg=cfg,
                                      abi=abi)
        init_func(args.source)  # 初始化分析跨合约序列
        assert check_cross_init(), "跨合约初始化失败"  # 检查是否初始化成功
        print("跨合约初始化成功......")

    def deploy_depend_contracts(self):
        generators = []
        if self.whole_compile_info is None:
            logger.error("没有找到编译信息, 退出程序!")
            sys.exit(-1)
        for depend_contract in self.depend_contracts:
            # 得到这个合约的interface
            interface, interface_mapper = get_interface_from_abi(self.whole_compile_info[depend_contract]['abi'])
            deployement_bytecode = self.whole_compile_info[depend_contract]['evm']['bytecode']['object']
            if "constructor" in interface:
                del interface['constructor']
            if "constructor" not in interface:
                result = self.instrumented_evm.deploy_contract(self.instrumented_evm.accounts[0],
                                                               deployement_bytecode)  # 将依赖合约部署
                if result.is_error:
                    logger.error("Problem while deploying contract %s using account %s. Error message: %s",
                                 depend_contract, self.instrumented_evm.accounts[0], result._error)
                    # 这里原本是退出程序, 但依赖合约部署失败可以不退出, 不影响主程序的大部分fuzz
                else:
                    contract_address = encode_hex(result.msg.storage_address)
                    self.instrumented_evm.accounts.append(contract_address)
                    self.env.nr_of_transactions += 1
                    # logger.info(
                    #     f"依赖合约 {depend_contract} deployed at\t%s, 由{self.instrumented_evm.accounts[0]}创建",
                    #     contract_address)
                    logger.info(
                        f"Dependent contract {depend_contract} deployed at\t%s, created by {self.instrumented_evm.accounts[0]}",
                        contract_address)
                    # 
                    settings.TRANS_INFO[depend_contract] = contract_address
                    settings.DEPLOYED_CONTRACT_ADDRESS[depend_contract] = contract_address
                    generator = Generator(interface=interface, bytecode=deployement_bytecode,
                                          accounts=self.instrumented_evm.accounts, contract=contract_address,
                                          interface_mapper=interface_mapper, contract_name=depend_contract,
                                          sol_path=self.args.source)
                    generators.append(generator)
        return generators

    def run(self):
        contract_address = None
        self.instrumented_evm.create_fake_accounts()
        if self.args.cross_contract == 1:  # 若开启了跨合约模式
            generators = self.deploy_depend_contracts()  # 先部署依赖合约
        else:
            generators = []
        if self.args.source:
            for transaction in self.blockchain_state:  # 如果块内有初始事务, 执行他们
                if transaction['from'].lower() not in self.instrumented_evm.accounts:
                    self.instrumented_evm.accounts.append(
                        self.instrumented_evm.create_fake_account(transaction['from']))

                if not transaction['to']:
                    result = self.instrumented_evm.deploy_contract(transaction['from'], transaction['input'],
                                                                   int(transaction['value']), int(transaction['gas']),
                                                                   int(transaction['gasPrice']))
                    if result.is_error:
                        logger.error("Problem while deploying contract %s using account %s. Error message: %s",
                                     self.contract_name, transaction['from'], result._error)
                        sys.exit(-2)
                    else:
                        contract_address = encode_hex(result.msg.storage_address)
                        self.instrumented_evm.accounts.append(contract_address)
                        self.env.nr_of_transactions += 1
                        logger.debug("Contract deployed at %s", contract_address)
                        self.env.other_contracts.append(to_canonical_address(contract_address))
                        cc, _ = get_pcs_and_jumpis(
                            self.instrumented_evm.get_code(to_canonical_address(contract_address)).hex())
                        self.env.len_overall_pcs_with_children += len(cc)
                else:
                    input = {}
                    input["block"] = {}
                    input["transaction"] = {
                        "from": transaction["from"],
                        "to": transaction["to"],
                        "gaslimit": int(transaction["gas"]),
                        "value": int(transaction["value"]),
                        "data": transaction["input"]
                    }
                    input["global_state"] = {}
                    out = self.instrumented_evm.deploy_transaction(input, int(transaction["gasPrice"]))

            if "constructor" in self.interface:
                del self.interface["constructor"]

            if not contract_address:
                if "constructor" not in self.interface:
                    result = self.instrumented_evm.deploy_contract(self.instrumented_evm.accounts[0],
                                                                   self.deployement_bytecode,
                                                                   deploy_args=self.args.constructor_args,
                                                                   deploy_mode=settings.CROSS_INIT_MODE)
                    if result.is_error:
                        logger.error("Problem while deploying contract %s using account %s. Error message: %s",
                                     self.contract_name, self.instrumented_evm.accounts[0], result._error)
                        sys.exit(-2)
                    else:
                        contract_address = encode_hex(result.msg.storage_address)
                        self.instrumented_evm.accounts.append(contract_address)
                        self.env.nr_of_transactions += 1
                        logger.info("主Contract deployed at %s", contract_address)
                        # 将合约的部署情况存储起来
                        settings.TRANS_INFO[self.contract_name] = contract_address
                        settings.DEPLOYED_CONTRACT_ADDRESS[self.contract_name] = contract_address

            if contract_address in self.instrumented_evm.accounts:
                self.instrumented_evm.accounts.remove(contract_address)

            self.env.overall_pcs, self.env.overall_jumpis = get_pcs_and_jumpis(
                self.instrumented_evm.get_code(to_canonical_address(contract_address)).hex())

        if self.args.abi:
            contract_address = self.args.contract

        self.instrumented_evm.create_snapshot()  # 部署所有合约后, 创建快照

        generator = Generator(interface=self.interface,
                              bytecode=self.deployement_bytecode,
                              accounts=self.instrumented_evm.accounts,
                              contract=contract_address,
                              other_generators=generators,
                              interface_mapper=self.interface_mapper,
                              contract_name=self.contract_name,
                              sol_path=self.args.source)

        # update the generator with the interface of the other contracts
        all_generators = [generator] + generators
        for gen in generators:
            gen.update_other_generators(all_generators, generator.total_interface_mapper)

        # Create initial population
        size = 2 * len(self.interface)
        population = Population(indv_template=Individual(generator=generator, other_generators=generators),
                                indv_generator=generator,
                                size=settings.POPULATION_SIZE if settings.POPULATION_SIZE else size,
                                other_generators=generators).init(init_seed=False)

        # Create genetic operators
        if self.args.data_dependency:
            selection = DataDependencyLinearRankingSelection(env=self.env)  # 基于Read After Write关系的种子选择
            crossover = DataDependencyCrossover(pc=settings.PROBABILITY_CROSSOVER, env=self.env)  # 基于数据流的交叉策略
            mutation = Mutation(pm=settings.PROBABILITY_MUTATION)
        else:
            selection = LinearRankingSelection()
            crossover = Crossover(pc=settings.PROBABILITY_CROSSOVER)
            mutation = Mutation(pm=settings.PROBABILITY_MUTATION)

        # Create and run our evolutionary fuzzing engine
        engine = EvolutionaryFuzzingEngine(population=population, selection=selection, crossover=crossover,
                                           mutation=mutation,
                                           mapping=get_function_signature_mapping(self.env.abi))
        engine.fitness_register(lambda x: fitness_function(x, self.env))  # 计算x的适应度, x是individual
        engine.analysis.append(ExecutionTraceAnalyzer(self.env))  # 注册了执行器

        self.env.execution_begin = time.time()
        self.env.population = population
        settings.GLOBAL_ENV = self.env

        engine.run(ng=settings.GENERATIONS)

        if self.env.args.cfg:
            if self.env.args.source:
                self.env.cfg.save_control_flow_graph(
                    os.path.splitext(self.env.args.source)[0] + '-' + self.contract_name, 'pdf')
            elif self.env.args.abi:
                self.env.cfg.save_control_flow_graph(
                    os.path.join(os.path.dirname(self.env.args.abi), self.contract_name), 'pdf')

        self.instrumented_evm.reset()
        settings.TRANS_INFO["end_time"] = str(datetime.now())


def main():
    """
    Hàm chính của chương trình.
    Hàm `main()` thực hiện các bước sau:
    - Phân tích các đối số khởi chạy.
    - Khởi tạo logger để ghi nhận thông tin hoạt động.
    - Kiểm tra và xử lý tệp kết quả nếu tồn tại.
    - Thiết lập seed ngẫu nhiên dựa trên đối số hoặc giá trị ngẫu nhiên.
    - Khởi tạo và cấu hình môi trường ảo Ethereum (EVM).
    - Tạo và cấu hình solver Z3 để sử dụng trong quá trình phân tích.
    - Xử lý trạng thái blockchain nếu được cung cấp.
    - Biên dịch mã nguồn Solidity để lấy bytecode và ABI nếu được cung cấp.
    - Khởi chạy quá trình fuzzing trên hợp đồng thông minh hoặc ABI đã cho.
    Hàm không trả về giá trị nào và sẽ kết thúc chương trình nếu phát hiện lỗi nghiêm trọng.
    """
    
    args = launch_argument_parser()

    logger = initialize_logger("Main    ")

    # Check if contract has already been analyzed
    if args.results and os.path.exists(args.results):
        os.remove(args.results)
        logger.info("Contract " + str(args.source) + " has already been analyzed: " + str(args.results))
        # logger.info(f"原始的测试输出文件{args.results}已被删除")
        logger.info(f"The original test output file {args.results} has been deleted")

    # Initializing random
    if args.seed:
        seed = args.seed
        if not "PYTHONHASHSEED" in os.environ:
            logger.debug("Please set PYTHONHASHSEED to '1' for Python's hash function to behave deterministically.")
    else:
        seed = random.random()
    random.seed(seed)
    logger.title("Initializing seed to %s", seed)

    # Initialize EVM
    instrumented_evm = InstrumentedEVM(settings.RPC_HOST, settings.RPC_PORT)
    instrumented_evm.set_vm_by_name(settings.EVM_VERSION)

    # Create Z3 solver instance
    solver = Solver()
    solver.set("timeout", settings.SOLVER_TIMEOUT)

    # Parse blockchain state if provided
    blockchain_state = []
    if args.blockchain_state:
        if args.blockchain_state.endswith(".json"):
            with open(args.blockchain_state) as json_file:
                for line in json_file.readlines():
                    blockchain_state.append(json.loads(line))
        elif args.blockchain_state.isnumeric():
            settings.BLOCK_HEIGHT = int(args.blockchain_state)
            instrumented_evm.set_vm(settings.BLOCK_HEIGHT)
        else:
            logger.error("Unsupported input file: " + args.blockchain_state)
            sys.exit(-1)

    # Compile source code to get deployment bytecode, runtime bytecode and ABI
    if args.source:
        if args.source.endswith(".sol"):
            compiler_output = compile(args.solc_version, settings.EVM_VERSION, args.source)
            if not compiler_output:
                logger.error("No compiler output for: " + args.source)
                sys.exit(-1)
            for contract_name, contract in compiler_output['contracts'][args.source].items():
                if args.contract and contract_name != args.contract:
                    continue
                if contract['abi'] and contract['evm']['bytecode']['object'] and contract['evm']['deployedBytecode'][
                    'object']:
                    source_map = SourceMap(':'.join([args.source, contract_name]), compiler_output)
                    Fuzzer(contract_name, contract["abi"], contract['evm']['bytecode']['object'],
                           contract['evm']['deployedBytecode']['object'], instrumented_evm, blockchain_state, solver,
                           args, seed, source_map, compiler_output['contracts'][args.source]).run()
        else:
            logger.error("Unsupported input file: " + args.source)
            sys.exit(-1)

    if args.abi:
        with open(args.abi) as json_file:
            abi = json.load(json_file)
            runtime_bytecode = instrumented_evm.get_code(to_canonical_address(args.contract)).hex()
            Fuzzer(args.contract, abi, None, runtime_bytecode, instrumented_evm, blockchain_state, solver, args,
                   seed).run()


def launch_argument_parser():
    parser = argparse.ArgumentParser()

    # Contract parameters
    group1 = parser.add_mutually_exclusive_group(required=True)
    group1.add_argument("-s", "--source", type=str,
                        help="Solidity smart contract source code file (.sol).")
    group1.add_argument("-a", "--abi", type=str,
                        help="Smart contract ABI file (.json).")

    # group2 = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument("-c", "--contract", type=str,
                        help="Contract name to be fuzzed (if Solidity source code file provided) or blockchain contract address (if ABI file provided).")

    parser.add_argument("-b", "--blockchain-state", type=str,
                        help="Initialize fuzzer with a blockchain state by providing a JSON file (if Solidity source code file provided) or a block number (if ABI file provided).")

    # Compiler parameters
    parser.add_argument("--solc", help="Solidity compiler version (default '" + str(
        solcx.get_solc_version()) + "'). Installed compiler versions: " + str(
        solcx.get_installed_solc_versions()) + ".",
                        action="store", dest="solc_version", type=str)
    parser.add_argument("--evm", help="Ethereum VM (default '" + str(
        settings.EVM_VERSION) + "'). Available VM's: 'homestead', 'byzantium' or 'petersburg'.", action="store",
                        dest="evm_version", type=str)

    # Evolutionary parameters
    group3 = parser.add_mutually_exclusive_group(required=False)
    group3.add_argument("-g", "--generations",
                        help="Number of generations (default " + str(settings.GENERATIONS) + ").", action="store",
                        dest="generations", type=int)
    group3.add_argument("-t", "--timeout",
                        help="Number of seconds for fuzzer to stop.", action="store",
                        dest="global_timeout", type=int)
    parser.add_argument("-n", "--population-size",
                        help="Size of the population.", action="store",
                        dest="population_size", type=int)
    parser.add_argument("-pc", "--probability-crossover",
                        help="Size of the population.", action="store",
                        dest="probability_crossover", type=float)
    parser.add_argument("-pm", "--probability-mutation",
                        help="Size of the population.", action="store",
                        dest="probability_mutation", type=float)

    # Miscellaneous parameters
    parser.add_argument("-r", "--results", type=str, help="Folder or JSON file where results should be stored.")
    parser.add_argument("--seed", type=float, help="Initialize the random number generator with a given seed.")
    parser.add_argument("--cfg", help="Build control-flow graph and highlight code coverage.", action="store_true")
    parser.add_argument("--rpc-host", help="Ethereum client RPC hostname.", action="store", dest="rpc_host", type=str)
    parser.add_argument("--rpc-port", help="Ethereum client RPC port.", action="store", dest="rpc_port", type=int)

    parser.add_argument("--data-dependency",
                        help="Disable/Enable data dependency analysis: 0 - Disable, 1 - Enable (default: 1)",
                        action="store",
                        dest="data_dependency", type=int)
    parser.add_argument("--constraint-solving",
                        help="Disable/Enable constraint solving: 0 - Disable, 1 - Enable (default: 1)", action="store",
                        dest="constraint_solving", type=int)
    parser.add_argument("--environmental-instrumentation",
                        help="Disable/Enable environmental instrumentation: 0 - Disable, 1 - Enable (default: 1)",
                        action="store",
                        dest="environmental_instrumentation", type=int)
    parser.add_argument("--max-individual-length",
                        help="Maximal length of an individual (default: " + str(settings.MAX_INDIVIDUAL_LENGTH) + ")",
                        action="store",
                        dest="max_individual_length", type=int)
    parser.add_argument("--max-symbolic-execution",
                        help="Maximum number of symbolic execution calls before restting population (default: " + str(
                            settings.MAX_SYMBOLIC_EXECUTION) + ")", action="store",
                        dest="max_symbolic_execution", type=int)

    # cross contract fuzz parameters
    parser.add_argument("--cross-contract", type=int, help="open cross contract mode, open -- 1, close -- 2 (default)",
                        action="store", dest="cross_contract", default=2)
    parser.add_argument("--depend-contracts", type=str, nargs="*",
                        help="main fuzzed contract depend those contracts, you should give some names.",
                        dest="depend_contracts")
    parser.add_argument("--trans-json-path", type=str, help="location to save trans info to json",
                        dest="trans_json_path")
    parser.add_argument("--solc-path-cross", type=str, help="solc path, used by cross-slither", dest="solc_path_cross")
    parser.add_argument("--constructor-args", type=str, nargs="*",
                        help="constructor args, like: [address, uint, .....]", dest="constructor_args")
    parser.add_argument("--open-trans-comp", type=int, help="open cross trans mode, open -- 1 (default), close -- 2",
                        action="store", dest="trans_comp", default=1)
    parser.add_argument("--trans-mode", type=int, help="trans support mode, open other -- 1, no exec other -- 2",
                        default=1, dest="trans_mode")
    parser.add_argument("--p-open-cross", type=int, help="use cross trans probability: (1~8)", default=5,
                        dest="p_open_cross")
    parser.add_argument("--cross-init-mode", type=int, help="cross init mode: 1 -- specify, 2 -- random, 3 -- close",
                        default=1, dest="cross_init_mode")
    parser.add_argument("--duplication", type=str, help="duplication mode: 0 -- close, 1 -- open", default='0',
                        dest="duplication")

    version = "ConFuzzius - Version 0.0.2 - "
    version += "\"By three methods we may learn wisdom:\n"
    version += "First, by reflection, which is noblest;\n"
    version += "Second, by imitation, which is easiest;\n"
    version += "And third by experience, which is the bitterest.\"\n"
    parser.add_argument("-v", "--version", action="version", version=version)

    args = parser.parse_args()

    if not args.contract:
        args.contract = ""

    if args.source and args.contract.startswith("0x"):
        parser.error("--source requires --contract to be a name, not an address.")
    if args.source and args.blockchain_state and args.blockchain_state.isnumeric():
        parser.error("--source requires --blockchain-state to be a file, not a number.")

    if args.abi and not args.contract.startswith("0x"):
        parser.error("--abi requires --contract to be an address, not a name.")
    if args.abi and args.blockchain_state and not args.blockchain_state.isnumeric():
        parser.error("--abi requires --blockchain-state to be a number, not a file.")

    if args.evm_version:
        settings.EVM_VERSION = args.evm_version
    if not args.solc_version:
        args.solc_version = solcx.get_solc_version()
    if args.generations:
        settings.GENERATIONS = args.generations
    if args.global_timeout:
        settings.GLOBAL_TIMEOUT = args.global_timeout
    if args.population_size:
        settings.POPULATION_SIZE = args.population_size
    if args.probability_crossover:
        settings.PROBABILITY_CROSSOVER = args.probability_crossover
    if args.probability_mutation:
        settings.PROBABILITY_MUTATION = args.probability_mutation

    if args.data_dependency is None:
        args.data_dependency = 1
    if args.constraint_solving is None:
        args.constraint_solving = 1
    if args.environmental_instrumentation is None:
        args.environmental_instrumentation = 1

    if args.environmental_instrumentation == 1:
        settings.ENVIRONMENTAL_INSTRUMENTATION = True
    elif args.environmental_instrumentation == 0:
        settings.ENVIRONMENTAL_INSTRUMENTATION = False

    if args.max_individual_length:
        settings.MAX_INDIVIDUAL_LENGTH = args.max_individual_length
    if args.max_symbolic_execution:
        settings.MAX_SYMBOLIC_EXECUTION = args.max_symbolic_execution

    if args.abi:
        settings.REMOTE_FUZZING = True

    if args.rpc_host:
        settings.RPC_HOST = args.rpc_host
    if args.rpc_port:
        settings.RPC_PORT = args.rpc_port

    # cross contract
    if args.contract is None or args.contract == "" or args.cross_contract == 2:
        args.cross_contract = 2  # close
        args.depend_contracts = []
        args.trans_json_path = None
    else:
        if args.contract is None or args.contract == "":
            print(
                '\033[42;31m!!!!!!if open cross contract mode, you need specify a main contract which will be fuzzed!!!!!!\033[0m')
            print('\033[42;31m!!!!!!use --contract [Example]!!!!!!\033[0m')
            sys.exit(-1)
        if args.depend_contracts is None:
            print(
                '\033[42;31m!!!!!!if open cross contract mode, you need specify some contract names which depended by main contract!!!!!!\033[0m')
            print('\033[42;31m!!!!!!use --depend-contracts [A B C]!!!!!!\033[0m')
            sys.exit(-1)
        if args.constructor_args is None:
            print('\033[42;31m!!!!!!if open cross contract mode, you need specify some constructor args!!!!!!\033[0m')
            print('\033[42;31m!!!!!!use --constructor-args [address, uint, .....]!!!!!!\033[0m')
            sys.exit(-1)
    if args.trans_json_path is not None:
        settings.TRANS_INFO_JSON_PATH = args.trans_json_path
        # print(f'\033[42;31m!!!!!!设置用于存储事务序列信息的json地址{settings.TRANS_INFO_JSON_PATH}!!!!!!\033[0m')
        print(f'\033[42;31m!!!!!! The JSON path for storing transaction sequence information is {settings.TRANS_INFO_JSON_PATH}!!!!!!\033[0m')
        if os.path.exists(settings.TRANS_INFO_JSON_PATH):
            # print(f'\033[42;31m!!!!!!用于存储事务序列信息的json地址{settings.TRANS_INFO_JSON_PATH}已经存在了, 现已覆盖!!!!!!\033[0m')
            print(f'\033[42;31m!!!!!! The JSON path for storing transaction sequence information {settings.TRANS_INFO_JSON_PATH} already exists and has been overwritten!!!!!!\033[0m')
    if args.trans_comp == 1:
        settings.TRANS_COMP_OPEN = True  
    elif args.trans_comp == 2:
        settings.TRANS_COMP_OPEN = False
    settings.MAIN_CONTRACT_NAME = args.contract
    settings.SOLC_PATH_CROSS = args.solc_path_cross
    settings.P_OPEN_CROSS = args.p_open_cross
    settings.CROSS_INIT_MODE = args.cross_init_mode
    settings.TRANS_SUPPORT_MODE = args.trans_mode
    if args.duplication == '0':
        settings.DUPLICATION = True
    else:
        settings.DUPLICATION = False
    if settings.SOLC_PATH_CROSS is None:
        print('\033[42;31m!!!!!!you need specify a solc path!!!!!!\033[0m')
        sys.exit(-1)

    return args


if '__main__' == __name__:
    main()
