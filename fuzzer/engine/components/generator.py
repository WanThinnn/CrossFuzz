#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import collections
from typing import List
from typing import Tuple
from fuzzer.utils import settings
from fuzzer.utils.transaction_seq_utils import gen_trans
from fuzzer.utils.utils import *

'''
Cung cấp các công cụ để tạo dữ liệu thử nghiệm và chuỗi giao dịch sử dụng trong quá trình fuzzing
hoặc thử nghiệm hợp đồng thông minh, giúp phát hiện các lỗi tiềm ẩn hoặc hành vi không mong muốn 
trong hợp đồng.
'''

# Định nghĩa giá trị lớn nhất cho số nguyên không dấu (unsigned integer) với kích thước từ 1 đến 32 byte.
UINT_MAX = {
    1: int("0xff", 16),
    2: int("0xffff", 16),
    3: int("0xffffff", 16),
    4: int("0xffffffff", 16),
    5: int("0xffffffffff", 16),
    6: int("0xffffffffffff", 16),
    7: int("0xffffffffffffff", 16),
    8: int("0xffffffffffffffff", 16),
    9: int("0xffffffffffffffffff", 16),
    10: int("0xffffffffffffffffffff", 16),
    11: int("0xffffffffffffffffffffff", 16),
    12: int("0xffffffffffffffffffffffff", 16),
    13: int("0xffffffffffffffffffffffffff", 16),
    14: int("0xffffffffffffffffffffffffffff", 16),
    15: int("0xffffffffffffffffffffffffffffff", 16),
    16: int("0xffffffffffffffffffffffffffffffff", 16),
    17: int("0xffffffffffffffffffffffffffffffffff", 16),
    18: int("0xffffffffffffffffffffffffffffffffffff", 16),
    19: int("0xffffffffffffffffffffffffffffffffffffff", 16),
    20: int("0xffffffffffffffffffffffffffffffffffffffff", 16),
    21: int("0xffffffffffffffffffffffffffffffffffffffffff", 16),
    22: int("0xffffffffffffffffffffffffffffffffffffffffffff", 16),
    23: int("0xffffffffffffffffffffffffffffffffffffffffffffff", 16),
    24: int("0xffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    25: int("0xffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    26: int("0xffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    27: int("0xffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    28: int("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    29: int("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    30: int("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    31: int("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    32: int("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
}


# Định nghĩa giá trị lớn nhất cho số nguyên có dấu (signed integer) với kích thước từ 1 đến 32 byte.
INT_MAX = {
    1: int("0x7f", 16),
    2: int("0x7fff", 16),
    3: int("0x7fffff", 16),
    4: int("0x7fffffff", 16),
    5: int("0x7fffffffff", 16),
    6: int("0x7fffffffffff", 16),
    7: int("0x7fffffffffffff", 16),
    8: int("0x7fffffffffffffff", 16),
    9: int("0x7fffffffffffffffff", 16),
    10: int("0x7fffffffffffffffffff", 16),
    11: int("0x7fffffffffffffffffffff", 16),
    12: int("0x7fffffffffffffffffffffff", 16),
    13: int("0x7fffffffffffffffffffffffff", 16),
    14: int("0x7fffffffffffffffffffffffffff", 16),
    15: int("0x7fffffffffffffffffffffffffffff", 16),
    16: int("0x7fffffffffffffffffffffffffffffff", 16),
    17: int("0x7fffffffffffffffffffffffffffffffff", 16),
    18: int("0x7fffffffffffffffffffffffffffffffffff", 16),
    19: int("0x7fffffffffffffffffffffffffffffffffffff", 16),
    20: int("0x7fffffffffffffffffffffffffffffffffffffff", 16),
    21: int("0x7fffffffffffffffffffffffffffffffffffffffff", 16),
    22: int("0x7fffffffffffffffffffffffffffffffffffffffffff", 16),
    23: int("0x7fffffffffffffffffffffffffffffffffffffffffffff", 16),
    24: int("0x7fffffffffffffffffffffffffffffffffffffffffffffff", 16),
    25: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    26: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    27: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    28: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    29: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    30: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    31: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    32: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
}


# Định nghĩa giá trị nhỏ nhất (âm) của số nguyên có dấu với kích thước từ 1 đến 32 byte.
INT_MIN = {
    1: int("-0x80", 16),
    2: int("-0x8000", 16),
    3: int("-0x800000", 16),
    4: int("-0x80000000", 16),
    5: int("-0x8000000000", 16),
    6: int("-0x800000000000", 16),
    7: int("-0x80000000000000", 16),
    8: int("-0x8000000000000000", 16),
    9: int("-0x800000000000000000", 16),
    10: int("-0x80000000000000000000", 16),
    11: int("-0x8000000000000000000000", 16),
    12: int("-0x800000000000000000000000", 16),
    13: int("-0x80000000000000000000000000", 16),
    14: int("-0x8000000000000000000000000000", 16),
    15: int("-0x800000000000000000000000000000", 16),
    16: int("-0x80000000000000000000000000000000", 16),
    17: int("-0x8000000000000000000000000000000000", 16),
    18: int("-0x800000000000000000000000000000000000", 16),
    19: int("-0x80000000000000000000000000000000000000", 16),
    20: int("-0x8000000000000000000000000000000000000000", 16),
    21: int("-0x800000000000000000000000000000000000000000", 16),
    22: int("-0x80000000000000000000000000000000000000000000", 16),
    23: int("-0x8000000000000000000000000000000000000000000000", 16),
    24: int("-0x800000000000000000000000000000000000000000000000", 16),
    25: int("-0x80000000000000000000000000000000000000000000000000", 16),
    26: int("-0x8000000000000000000000000000000000000000000000000000", 16),
    27: int("-0x800000000000000000000000000000000000000000000000000000", 16),
    28: int("-0x80000000000000000000000000000000000000000000000000000000", 16),
    29: int("-0x8000000000000000000000000000000000000000000000000000000000", 16),
    30: int("-0x800000000000000000000000000000000000000000000000000000000000", 16),
    31: int("-0x80000000000000000000000000000000000000000000000000000000000000", 16),
    32: int("-0x8000000000000000000000000000000000000000000000000000000000000000", 16)
}

MAX_RING_BUFFER_LENGTH = 10 # Kích thước tối đa cho buffer vòng
MAX_ARRAY_LENGTH = 2 # Kích thước giới hạn của các mảng hoặc cấu trúc dữ liệu tương tự


class CircularSet: 
    '''
    Mô phỏng tập hợp vòng (circular set), lưu trữ các giá trị với khả năng 
    tự động thay thế giá trị cũ khi đạt đến giới hạn.
    '''
    def __init__(self, set_size=MAX_RING_BUFFER_LENGTH, initial_set=None): #Khởi tạo một tập hợp vòng với kích thước tối đa
        self._q = collections.deque(maxlen=set_size)
        if initial_set:
            self._q.extend(initial_set)

    @property
    def empty(self): # Kiểm tra xem tập hợp vòng có rỗng không
        return len(self._q) == 0

    def add(self, value): # Thêm một giá trị vào tập hợp vòng
        if value not in self._q:
            self._q.append(value)
        else:
            self._q.remove(value)
            self._q.append(value)

    def head_and_rotate(self): # Trả về giá trị ở cuối tập hợp và xoay vòng tập hợp
        value = self._q[-1]
        self._q.rotate(1)
        return value

    def discard(self, value): # Loại bỏ một giá trị khỏi tập hợp
        if value in self._q:
            self._q.remove(value)

    def __repr__(self): # Hiển thị tập hợp vòng
        return repr(self._q)


class Generator:
    """
    Là bộ sinh kiểm thử cho các hợp đồng thông minh. 
    Hỗ trợ tạo ra các chuỗi giao dịch (transaction sequences) có chứa 
    tham số dựa trên cấu trúc của giao diện (interface) và dữ liệu 
    đầu vào của hợp đồng.

    """

    def __init__(self, interface, bytecode, accounts, contract, other_generators=None, interface_mapper=None,
                 contract_name=None, sol_path=None): # Khởi tạo bộ sinh kiểm thử
        self.logger = initialize_logger("Generator")
        self.interface = interface
        self.interface_mapper = interface_mapper
        self.bytecode = bytecode
        self.accounts = accounts
        self.contract = contract  # Địa chỉ triển khai hợp đồng
        self.contract_name = contract_name  # Tên hợp đồng
        self.sol_path = sol_path  # Địa chỉ tệp hợp đồng, dùng cho phân tích giữa các hợp đồng
        self.other_generators = other_generators if other_generators is not None else []  # type:List[Generator]

        # Pools
        self.function_circular_buffer = CircularSet(set_size=len(self.interface), initial_set=set(self.interface))
        self.accounts_pool = {}
        self.amounts_pool = {}
        self.arguments_pool = {}
        self.timestamp_pool = {}
        self.blocknumber_pool = {}
        self.balance_pool = {}
        self.callresult_pool = {}
        self.gaslimit_pool = {}
        self.extcodesize_pool = {}
        self.returndatasize_pool = {}
        self.argument_array_sizes_pool = {}
        self.strings_pool = CircularSet()
        self.bytes_pool = CircularSet()

        # Bộ ánh xạ giao diện tổng thể interface_mapper
        self.total_interface_mapper = {self.contract_name: self.interface_mapper}
        for o_g in self.other_generators:
            self.total_interface_mapper[o_g.contract_name] = o_g.total_interface_mapper[o_g.contract_name]

    def update_other_generators(self, _other_generators, _total_interface_mapper): # Cập nhật các bộ sinh kiểm thử khác
        self.other_generators = _other_generators
        self.total_interface_mapper = _total_interface_mapper

    def generate_individual_by_cross(self): # Tạo chuỗi giao dịch dựa trên phương pháp cross
        """
        Dựa trên một chuỗi đã chỉ định, tạo ra một chuỗi chứa các tham số.
        """
        individual = []
        for o_g in self.other_generators:
            individual.extend(o_g.generate_constructor())
        real_individual = []
        if self.sol_path is not None:
            target_trans = settings.TRANS_CROSS_BAD_INDVS.pop()
            if len(target_trans[0].chromosome) >= settings.MAX_INDIVIDUAL_LENGTH:
                return target_trans[0].chromosome
            ret = gen_trans(target_trans, self.total_interface_mapper)
            for supply_func in ret:
                if supply_func is None:
                    break
                c_name, f_name = supply_func.split(".")
                if c_name == self.contract_name:
                    function, argument_types = self.get_specific_function_with_argument_types_without_arg_support(
                        f_name)
                    real_individual.extend(self.generate_individual(function, argument_types))
                else:
                    for o_g in self.other_generators:
                        if c_name == o_g.contract_name:
                            function, argument_types = o_g.get_specific_function_with_argument_types_without_arg_support(
                                f_name)
                            real_individual.extend(o_g.generate_individual(function, argument_types))
                            break
        if len(real_individual) == 0:  # Nếu không tìm thấy chuỗi giao dịch nào
            individual.extend(self.generate_randon_individual_without_constructor())
        else:
            individual.extend(real_individual)
        return individual

    def generate_constructor(self):
        """
        Tạo một chuỗi giao dịch chứa constructor
        """
        individual = []
        if "constructor" in self.interface and self.bytecode:
            arguments = ["constructor"]
            for index in range(len(self.interface["constructor"])):
                arguments.append(self.get_random_argument(self.interface["constructor"][index], "constructor", index))
            individual.append({
                "account": self.get_random_account("constructor"),
                "contract": self.bytecode,
                "amount": self.get_random_amount("constructor"),
                "arguments": arguments,
                "blocknumber": self.get_random_blocknumber("constructor"),
                "timestamp": self.get_random_timestamp("constructor"),
                "gaslimit": self.get_random_gaslimit("constructor"),
                "returndatasize": dict()
            })
        return individual

    def generate_individual(self, function, argument_types, default_value=False): # Tạo một giao dịch chứa tham số cho một hàm cụ thể
        """
        Tạo một chuỗi giao dịch chứa một hàm cụ thể
        """
        individual = []
        arguments = [function]  # Tham số đầu tiên nhất định là hash của hàm này
        for index in range(len(argument_types)):
            arguments.append(self.get_random_argument(argument_types[index], function, index))
        individual.append({
            "account": self.get_random_account(function),
            "contract": self.contract,
            "amount": self.get_random_amount(function),
            "arguments": arguments,
            "blocknumber": self.get_random_blocknumber(function),
            "timestamp": self.get_random_timestamp(function),
            "gaslimit": self.get_random_gaslimit(function),
            "call_return": dict(),
            "extcodesize": dict(),
            "returndatasize": dict()
        })

        address, call_return_value = self.get_random_callresult_and_address(function)
        individual[-1]["call_return"] = {address: call_return_value}

        address, extcodesize_value = self.get_random_extcodesize_and_address(function)
        individual[-1]["extcodesize"] = {address: extcodesize_value}

        address, value = self.get_random_returndatasize_and_address(function)
        individual[-1]["returndatasize"] = {address: value}
        return individual

    def generate_randon_individual_without_constructor(self, func_hash=None, func_args_types=None, default_value=False): # giao dịch không chứa hàm khởi tạo (chỉ dùng hàm ngẫu nhiên)
        individual = []
        if func_hash is not None and func_args_types is not None:
            individual.extend(self.generate_individual(func_hash, func_args_types, default_value))
            return individual
        else:
            function, argument_types = self.get_random_function_with_argument_types()  # Chọn ngẫu nhiên một hàm và lấy kiểu tham số của nó
            individual.extend(self.generate_individual(function, argument_types))
            return individual

    def generate_random_individual(self, func_hash=None, func_args_types=None, default_value=False): # Tạo chuỗi giao dịch hoàn chỉnh, bao gồm cả hàm khởi tạo (constructor) và hàm ngẫu nhiên
        """
        Tạo một chuỗi giao dịch
        """
        individual = []  # Một chuỗi giao dịch, bên trong có nhiều lời gọi hàm

        # Thêm lời gọi hàm của hợp đồng chính
        # Đầu tiên là hàm khởi tạo
        individual.extend(self.generate_constructor())

        # Chọn ngẫu nhiên một hàm và lấy kiểu tham số của nó
        individual.extend(
            self.generate_randon_individual_without_constructor(func_hash, func_args_types, default_value))

        return individual

    def generate_random_input(self): # Tạo dữ liệu đầu vào ngẫu nhiên
        input = {}

        function, argument_types = self.get_random_function_with_argument_types()
        arguments = [function]
        for index in range(len(argument_types)):
            arguments.append(self.get_random_argument(argument_types[index], function, index))
        input = {
            "account": self.get_random_account(function),
            "contract": self.contract,
            "amount": self.get_random_amount(function),
            "arguments": arguments,
            "blocknumber": self.get_random_blocknumber(function),
            "timestamp": self.get_random_timestamp(function),
            "gaslimit": self.get_random_gaslimit(function),
            "returndatasize": dict()
        }

        address, value = self.get_random_returndatasize_and_address(function)
        input["returndatasize"] = {address: value}

        return input

    def get_random_function_with_argument_types(self): # Chọn ngẫu nhiên một hàm từ hợp đồng và trả về hàm đó cùng với các kiểu đối số tương ứng
        function_hash = self.function_circular_buffer.head_and_rotate()
        if function_hash == "constructor":
            function_hash = self.function_circular_buffer.head_and_rotate()
        return function_hash, self.interface[function_hash]

    def get_specific_function_with_argument_types(self, function_signature): # Trả về hàm cụ thể và kiểu đối số tương ứng
        return self.interface_mapper[function_signature], self.interface[self.interface_mapper[function_signature]]

    def get_specific_function_with_argument_types_without_arg_support(self, function_name):
        for f_name_args, f_sign in self.interface_mapper.items():
            if f_name_args.startswith(function_name):
                return self.get_specific_function_with_argument_types(f_name_args) # Trả về hàm cụ thể không cần đối số từ bảng ánh xạ.

    #
    # TIMESTAMP
    #

    def add_timestamp_to_pool(self, function, timestamp): # Thêm timestamp vào  nhóm (pool) cho hàm cụ thể
        if not function in self.timestamp_pool:
            self.timestamp_pool[function] = CircularSet()
        self.timestamp_pool[function].add(timestamp)

    def get_random_timestamp(self, function):
        if function in self.timestamp_pool:
            return self.timestamp_pool[function].head_and_rotate()
        return None

    def remove_timestamp_from_pool(self, function, timestamp): # Loại bỏ timestamp khỏi nhóm (pool) cho hàm cụ thể
        if function in self.timestamp_pool:
            self.timestamp_pool[function].discard(timestamp)
            if self.timestamp_pool[function].empty:
                del self.timestamp_pool[function]

    #
    # BLOCKNUMBER
    #

    def add_blocknumber_to_pool(self, function, blocknumber): # Thêm blocknumber vào nhóm (pool) cho hàm cụ thể
        if not function in self.blocknumber_pool: 
            self.blocknumber_pool[function] = CircularSet()
        self.blocknumber_pool[function].add(blocknumber)

    def get_random_blocknumber(self, function): # Lấy một blocknumber ngẫu nhiên từ nhóm (pool) cho hàm cụ thể
        if function in self.blocknumber_pool:
            return self.blocknumber_pool[function].head_and_rotate()
        return None

    def remove_blocknumber_from_pool(self, function, blocknumber): # Loại bỏ blocknumber khỏi nhóm (pool) cho hàm cụ thể
        if function in self.blocknumber_pool:
            self.blocknumber_pool[function].discard(blocknumber)
            if self.blocknumber_pool[function].empty:
                del self.blocknumber_pool[function]

    #
    # BALANCE
    #

    def add_balance_to_pool(self, function, balance): # Thêm balance vào nhóm (pool) cho hàm cụ thể
        if not function in self.balance_pool:
            self.balance_pool[function] = CircularSet()
        self.balance_pool[function].add(balance)

    def get_random_balance(self, function): # Lấy một balance ngẫu nhiên từ nhóm (pool) cho hàm cụ thể
        if function in self.balance_pool:
            return self.balance_pool[function].head_and_rotate()
        return None

    #
    # CALL RESULT
    #

    def add_callresult_to_pool(self, function, address, result): # Thêm kết quả gọi hàm vào nhóm (pool) cho hàm cụ thể
        if not function in self.callresult_pool:
            self.callresult_pool[function] = dict()
        if not address in self.callresult_pool[function]:
            self.callresult_pool[function][address] = CircularSet()
        self.callresult_pool[function][address].add(result)

    def get_random_callresult_and_address(self, function): # Lấy một kết quả gọi hàm ngẫu nhiên từ nhóm (pool) cho hàm cụ thể
        if function in self.callresult_pool:
            address = random.choice(list(self.callresult_pool[function].keys()))
            value = self.callresult_pool[function][address].head_and_rotate()
            return address, value
        return None, None

    def get_random_callresult(self, function, address): # Lấy một kết quả gọi hàm ngẫu nhiên từ nhóm (pool) cho hàm cụ thể
        if function in self.callresult_pool:
            if address in self.callresult_pool[function]:
                value = self.callresult_pool[function][address].head_and_rotate()
                return value
        return None

    def remove_callresult_from_pool(self, function, address, result): # Loại bỏ kết quả gọi hàm khỏi nhóm (pool) cho hàm cụ thể
        if function in self.callresult_pool and address in self.callresult_pool[function]:
            self.callresult_pool[function][address].discard(result)
            if self.callresult_pool[function][address].empty:
                del self.callresult_pool[function][address]
                if len(self.callresult_pool[function]) == 0:
                    del self.callresult_pool[function]

    #
    # EXTCODESIZE
    #

    def add_extcodesize_to_pool(self, function, address, size): # Thêm extcodesize vào nhóm (pool) cho hàm cụ thể
        if not function in self.extcodesize_pool:
            self.extcodesize_pool[function] = dict()
        if not address in self.extcodesize_pool[function]:
            self.extcodesize_pool[function][address] = CircularSet()
        self.extcodesize_pool[function][address].add(size)

    def get_random_extcodesize_and_address(self, function): # Trả về kích thước mã hợp đồng ngẫu nhiên và địa chỉ từ nhóm
        if function in self.extcodesize_pool:
            address = random.choice(list(self.extcodesize_pool[function].keys()))
            return address, self.extcodesize_pool[function][address].head_and_rotate()
        return None, None

    def get_random_extcodesize(self, function, address): # Trả về kích thước mã hợp đồng ngẫu nhiên từ nhóm
        if function in self.extcodesize_pool:
            if address in self.extcodesize_pool[function]:
                return self.extcodesize_pool[function][address].head_and_rotate()
        return None

    def remove_extcodesize_from_pool(self, function, address, size): # Loại bỏ kích thước mã hợp đồng khỏi nhóm
        if function in self.extcodesize_pool and address in self.extcodesize_pool[function]:
            self.extcodesize_pool[function][address].discard(size)
            if self.extcodesize_pool[function][address].empty:
                del self.extcodesize_pool[function][address]
                if len(self.extcodesize_pool[function]) == 0:
                    del self.extcodesize_pool[function]

    #
    # RETURNDATASIZE
    #

    def add_returndatasize_to_pool(self, function, address, size): # Thêm kích thước dữ liệu trả về vào nhóm cho một địa chỉ
        if not function in self.returndatasize_pool:
            self.returndatasize_pool[function] = dict()
        if not address in self.returndatasize_pool[function]:
            self.returndatasize_pool[function][address] = CircularSet()
        self.returndatasize_pool[function][address].add(size)

    def get_random_returndatasize_and_address(self, function):  # Trả về kích thước dữ liệu trả về ngẫu nhiên và địa chỉ từ
        if function in self.returndatasize_pool:
            address = random.choice(list(self.returndatasize_pool[function].keys()))
            return address, self.returndatasize_pool[function][address].head_and_rotate()
        return None, None

    def get_random_returndatasize(self, function, address): # Trả về kích thước dữ liệu trả về ngẫu nhiên từ nhóm
        if function in self.returndatasize_pool:
            if address in self.returndatasize_pool[function]:
                return self.returndatasize_pool[function][address].head_and_rotate()
        return None

    def remove_returndatasize_from_pool(self, function, address, size): # Loại bỏ kích thước dữ liệu trả về khỏi nhóm
        if function in self.returndatasize_pool and address in self.returndatasize_pool[function]:
            self.returndatasize_pool[function][address].discard(size)
            if self.returndatasize_pool[function][address].empty:
                del self.returndatasize_pool[function][address]
                if len(self.returndatasize_pool[function]) == 0:
                    del self.returndatasize_pool[function]

    #
    # GASLIMIT
    #

    def add_gaslimit_to_pool(self, function, gaslimit): # Thêm giới hạn gas vào nhóm cho hàm.
        if not function in self.gaslimit_pool:
            self.gaslimit_pool[function] = CircularSet()
        self.gaslimit_pool[function].add(gaslimit)

    def remove_gaslimit_from_pool(self, function, gaslimit): # Loại bỏ giới hạn gas khỏi nhóm của hàm
        if function in self.gaslimit_pool:
            self.gaslimit_pool[function].discard(gaslimit)
            if self.gaslimit_pool[function].empty:
                del self.gaslimit_pool[function]

    def clear_gaslimits_in_pool(self, function): # Trả về giới hạn gas từ nhóm của hàm
        if function in self.gaslimit_pool:
            del self.gaslimit_pool[function]

    def get_random_gaslimit(self, function): # Trả về giới hạn gas ngẫu nhiên từ nhóm của hàm
        if function in self.gaslimit_pool:
            return self.gaslimit_pool[function].head_and_rotate()
        return settings.GAS_LIMIT

    #
    # ACCOUNTS
    #

    def add_account_to_pool(self, function, account): # Thêm tài khoản vào nhóm cho hàm cụ thể
        if not function in self.accounts_pool:
            self.accounts_pool[function] = CircularSet()
        self.accounts_pool[function].add(account)

    def remove_account_from_pool(self, function, account):
        if function in self.accounts_pool:
            self.accounts_pool[function].discard(account)
            if self.accounts_pool[function].empty:
                del self.accounts_pool[function]

    def clear_accounts_in_pool(self, function): # Xóa tất cả tài khoản khỏi nhóm của hàm
        if function in self.accounts_pool:
            self.accounts_pool[function] = CircularSet()

    def get_random_account_from_pool(self, function): # Trả về một tài khoản ngẫu nhiên từ nhóm của hàm
        return self.accounts_pool[function].head_and_rotate()

    def get_random_account(self, function): # Trả về một tài khoản ngẫu nhiên từ danh sách tài khoản
        if function in self.accounts_pool:
            return self.get_random_account_from_pool(function)
        else:
            return random.choice(self.accounts)

    #
    # AMOUNTS
    #

    def add_amount_to_pool(self, function, amount): # Thêm số lượng vào nhóm cho hàm cụ thể
        if not function in self.amounts_pool:
            self.amounts_pool[function] = CircularSet()
        self.amounts_pool[function].add(amount)

    def remove_amount_from_pool(self, function, amount): # Loại bỏ số lượng khỏi nhóm của hàm
        if function in self.amounts_pool:
            self.amounts_pool[function].discard(amount)
            if self.amounts_pool[function].empty:
                del self.amounts_pool[function]

    def get_random_amount_from_pool(self, function): # Trả về số lượng ngẫu nhiên từ nhóm của hàm
        return self.amounts_pool[function].head_and_rotate()

    def get_random_amount(self, function): # Trả về số lượng ngẫu nhiên
        if function in self.amounts_pool: 
            amount = self.get_random_amount_from_pool(function)
        else:
            # # Phiên bản gốc get_random_amount
            amount = random.randint(0, 1)
            self.add_amount_to_pool(function, amount)
            self.add_amount_to_pool(function, 1 - amount)
            # Để bao phủ các trường hợp giá trị tiền ở mức Ether, trường hợp trên có giá trị tối đa là 1 wei
            # if random.choice([True, True, False]):
            #     for level, multiply in [("Ether", 10 ** 18), ("Wei", 1)]:
            #         MAX_AMOUNT = 10 * multiply
            #         amount = random.randint(0, MAX_AMOUNT)
            #         self.add_amount_to_pool(function, amount)
        return amount

    #
    # STRINGS
    #

    def add_string_to_pool(self, string): # Thêm một chuỗi vào danh sách lưu trữ chuỗi (strings_pool)
        self.strings_pool.add(string)

    def get_random_string_from_pool(self): # Lấy một chuỗi ngẫu nhiên từ danh sách và xoay vòng danh sách.
        return self.strings_pool.head_and_rotate()

    #
    # BYTES
    #

    def add_bytes_to_pool(self, string): # Thêm một chuỗi dạng bytes vào danh sách (bytes_pool)
        self.bytes_pool.add(string)

    def get_random_bytes_from_pool(self): # Lấy một chuỗi dạng bytes ngẫu nhiên từ danh sách và xoay vòng danh sách.
        return self.bytes_pool.head_and_rotate()

    #
    # FUNCTION ARGUMENTS
    #

    def add_parameter_array_size(self, function, parameter_index, array_size): # Thêm kích thước mảng tham số của một hàm cụ thể vào danh sách lưu trữ
        if function not in self.argument_array_sizes_pool:
            self.argument_array_sizes_pool[function] = dict()
        if parameter_index not in self.argument_array_sizes_pool[function]:
            self.argument_array_sizes_pool[function][parameter_index] = CircularSet()
        self.argument_array_sizes_pool[function][parameter_index].add(min(array_size, MAX_ARRAY_LENGTH))

    def _get_parameter_array_size_from_pool(self, function, argument_index): # Lấy kích thước mảng đã lưu trữ liên quan đến một tham số cụ thể
        return self.argument_array_sizes_pool[function][argument_index].head_and_rotate()

    def remove_parameter_array_size_from_pool(self, function, parameter_index, array_size): # Xóa kích thước mảng khỏi danh sách nếu không còn cần thiế
        if function in self.argument_array_sizes_pool and parameter_index in self.argument_array_sizes_pool[function]:
            self.argument_array_sizes_pool[function][parameter_index].discard(array_size)
            if self.argument_array_sizes_pool[function][parameter_index].empty:
                del self.argument_array_sizes_pool[function][parameter_index]
                if len(self.argument_array_sizes_pool[function]) == 0:
                    del self.argument_array_sizes_pool[function]

    def add_argument_to_pool(self, function, argument_index, argument): # Thêm một tham số cụ thể (hoặc danh sách tham số) vào danh sách lưu trữ liên quan đến một hàm.
        if type(argument) is list:
            for element in argument:
                self.add_argument_to_pool(function, argument_index, element)
            return
        if function not in self.arguments_pool:
            self.arguments_pool[function] = {}
        if argument_index not in self.arguments_pool[function]:
            self.arguments_pool[function][argument_index] = CircularSet()
        self.arguments_pool[function][argument_index].add(argument)

    def remove_argument_from_pool(self, function, argument_index, argument): # Xóa một tham số cụ thể (hoặc danh sách tham số) khỏi danh sách lưu trữ liên quan đến một hàm.
        if type(argument) is list:
            for element in argument:
                self.remove_argument_from_pool(function, argument_index, element)
            return
        if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
            self.arguments_pool[function][argument_index].discard(argument)
            if self.arguments_pool[function][argument_index].empty:
                del self.arguments_pool[function][argument_index]
                if len(self.arguments_pool[function]) == 0:
                    del self.arguments_pool[function]

    def _get_random_argument_from_pool(self, function, argument_index): # Lấy một tham số ngẫu nhiên từ danh sách tham số của một hàm.
        return self.arguments_pool[function][argument_index].head_and_rotate()

    def get_random_argument(self, type, function, argument_index): # Trả về tham số ngẫu nhiên dựa trên kiểu dữ liệu (type)
        # Boolean
        if type.startswith("bool"):
            # Array
            if "[" in type and "]" in type:  # Nếu là mảng
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                        if self._get_random_argument_from_pool(function, argument_index) == 0:
                            array.append(False)
                        else:
                            array.append(True)
                    else:
                        if random.randint(0, 1) == 0:
                            array.append(False)
                        else:
                            array.append(True)
                if len(sizes) > 1:  # Nếu là mảng 2 chiều
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    if self._get_random_argument_from_pool(function, argument_index) == 0:
                        return False
                    return True
                else:
                    if random.randint(0, 1) == 0:
                        return False
                    return True

        # Unsigned integer
        elif type.startswith("uint"):
            bytes = int(int(type.replace("uint", "").split("[")[0]) / 8)
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                        array.append(self._get_random_argument_from_pool(function, argument_index))
                    else:
                        array.append(self.get_random_unsigned_integer(0, UINT_MAX[bytes]))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    return self._get_random_argument_from_pool(function, argument_index)
                return self.get_random_unsigned_integer(0, UINT_MAX[bytes])  # Trả về một số nguyên không dấu

        # Signed integer
        elif type.startswith("int"):
            bytes = int(int(type.replace("int", "").split("[")[0]) / 8)
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                        array.append(self._get_random_argument_from_pool(function, argument_index))
                    else:
                        array.append(self.get_random_signed_integer(INT_MIN[bytes], INT_MAX[bytes]))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    return self._get_random_argument_from_pool(function, argument_index)
                return self.get_random_signed_integer(INT_MIN[bytes], INT_MAX[bytes]) # Trả về một số nguyên có dấu

        # Address
        elif type.startswith("address"):
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                        array.append(self._get_random_argument_from_pool(function, argument_index))
                    else:
                        array.append(random.choice(self.accounts))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    return self._get_random_argument_from_pool(function, argument_index)
                return random.choice(self.accounts)  # Trả về một địa chỉ ngẫu nhiên

        # String
        elif type.startswith("string"):
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    array.append(self.get_string(random.randint(0, MAX_ARRAY_LENGTH)))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    return self._get_random_argument_from_pool(function, argument_index)
                if self.strings_pool.empty:
                    self.add_string_to_pool(self.get_string(0))  # Ngẫu nhiên tạo chuỗi có độ dài bằng 0 và thêm vào pool.
                    self.add_string_to_pool(self.get_string(1))
                    self.add_string_to_pool(self.get_string(32))
                    self.add_string_to_pool(self.get_string(33))
                return self.get_random_string_from_pool()  # Ngẫu nhiên chọn một chuỗi từ pool.

        # Bytes1 ... Bytes32
        elif type.startswith("bytes1") or \
                type.startswith("bytes2") or \
                type.startswith("bytes3") or \
                type.startswith("bytes4") or \
                type.startswith("bytes5") or \
                type.startswith("bytes6") or \
                type.startswith("bytes7") or \
                type.startswith("bytes8") or \
                type.startswith("bytes9") or \
                type.startswith("bytes10") or \
                type.startswith("bytes11") or \
                type.startswith("bytes12") or \
                type.startswith("bytes13") or \
                type.startswith("bytes14") or \
                type.startswith("bytes15") or \
                type.startswith("bytes16") or \
                type.startswith("bytes17") or \
                type.startswith("bytes18") or \
                type.startswith("bytes19") or \
                type.startswith("bytes20") or \
                type.startswith("bytes21") or \
                type.startswith("bytes22") or \
                type.startswith("bytes23") or \
                type.startswith("bytes24") or \
                type.startswith("bytes25") or \
                type.startswith("bytes26") or \
                type.startswith("bytes27") or \
                type.startswith("bytes28") or \
                type.startswith("bytes29") or \
                type.startswith("bytes30") or \
                type.startswith("bytes31") or \
                type.startswith("bytes32"):
            length = int(type.replace("bytes", "").split("[")[0])
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                        array.append(self._get_random_argument_from_pool(function, argument_index))
                    else:
                        array.append(self.get_random_bytes(length))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    return self._get_random_argument_from_pool(function, argument_index)
                return self.get_random_bytes(random.randint(0, length))

        # Bytes
        elif type.startswith("bytes"):
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    array.append(self.get_random_bytes(random.randint(0, MAX_ARRAY_LENGTH)))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    return self._get_random_argument_from_pool(function, argument_index)
                if self.bytes_pool.empty:
                    self.add_bytes_to_pool(self.get_random_bytes(0))
                    self.add_bytes_to_pool(self.get_random_bytes(1))
                    self.add_bytes_to_pool(self.get_random_bytes(32))
                    self.add_bytes_to_pool(self.get_random_bytes(33))
                return self.get_random_bytes_from_pool()

        # Unknown type
        else:
            self.logger.error("Unsupported type: " + str(type))  # LKhông hỗ trợ các loại dữ liệu khác

    def _get_array_sizes(self, argument_index, function, type): # Lấy kích thước của mảng từ kiểu dữ liệu
        sizes = []
        for size in re.compile(r"\[(.*?)\]").findall(type):
            # Dynamic array
            if size == "":
                if function in self.argument_array_sizes_pool \
                        and argument_index in self.argument_array_sizes_pool[function]:
                    sizes.append(self._get_parameter_array_size_from_pool(function, argument_index))
                else:
                    sizes.append(random.randint(0, MAX_ARRAY_LENGTH))
            # Fixed size array
            else:
                sizes.append(int(size))
        return sizes

    @staticmethod
    def get_random_unsigned_integer(min, max): # Trả về một số nguyên không dấu ngẫu nhiên trong khoảng từ min đến max
        seed = int(random.uniform(-2, 2))
        if seed == -1:
            return random.choice([min, min + 1, min + 2])
        elif seed == 1:
            return random.choice([max, max - 1, max - 2])
        else:
            return random.randint(min, max)

    @staticmethod
    def get_random_signed_integer(min, max):
        seed = int(random.uniform(-2, 2))
        if seed == -1:
            return random.choice([0, -1, min, min + 1])
        elif seed == 1:
            return random.choice([0, 1, max, max - 1])
        else:
            return random.randint(min, max)

    @staticmethod
    def get_string(length):  # Tạo một chuỗi có độ dài xác định, với tất cả ký tự là A.
        return ''.join('A' for _ in range(length))

    @staticmethod
    def get_random_bytes(length): # Tạo một chuỗi bytes ngẫu nhiên với độ dài xác định.
        """
        随机获得length长度的字节序列
        """
        return bytearray(random.getrandbits(8) for _ in range(length))
