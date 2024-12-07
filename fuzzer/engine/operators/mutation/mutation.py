#!/usr/bin/env python3
# -*- coding: utf-8 -*-

''' Mutation implementation. '''

import random

from utils import settings
from ...plugin_interfaces.operators.mutation import Mutation

"""
    Lớp Mutation kế thừa từ lớp Mutation trong module plugin_interfaces.operators.mutation
    Lớp này thực hiện việc đột biến cá thể bằng cách thay đổi các gene trong chromosome của cá thể.
"""

class Mutation(Mutation):
    def __init__(self, pm):
        '''
        Nhận tham số pm (xác suất đột biến) khi khởi tạo một đối tượng Mutation.
        Nếu pm không nằm trong khoảng (0.0, 1.0], chương trình sẽ ném ra lỗi ValueError
        '''
        if pm <= 0.0 or pm > 1.0:
            raise ValueError('Invalid mutation probability')

        self.pm = pm

    def mutate(self, individual, engine):
        """
        Nhận hai tham số: individual (đại diện cho một cá thể) và engine (động cơ hoặc môi trường thực thi)
        """
        for gene in individual.chromosome:
            # Xét từng gene trong individual.chromosome, sau đó thực hiện thay đổi (đột biến) các trường của gene
            function_hash = gene["arguments"][0]
            for element in gene:    
                """
                Nếu gene trong indivial.chromosome là account, amount, gaslimit: Giá trị thay đổi ngẫu nhiên theo các hàm tương ứng 
                từ individual.generator nếu vượt qua ngưỡng random.random() <= self.pm
                """
                if element == "account" and random.random() <= self.pm:
                    gene["account"] = individual.generator.get_random_account(function_hash)
                elif element == "amount" and random.random() <= self.pm:
                    gene["amount"] = individual.generator.get_random_amount(function_hash)
                elif element == "gaslimit" and random.random() <= self.pm:
                    gene["gaslimit"] = individual.generator.get_random_gaslimit(function_hash)
                else:
                    """
                    Nếu gene trong indivial.chromosome là arguments,đồng thời gene có chứa hàm băm (function_hash) trong danh sách interface
                    của generator, thì thực hiện thay đổi ngẫu nhiên các giá trị của arguments trong gene
                    Trong trường hợp phần tử là "arguments" mà xác suất ngẫu nhiên lớn hơn pm, nó sẽ tiếp tục vòng lặp mà không thay đổi giá trị xác suất 
                    ngẫu nhiên lớn hơn pm, nó sẽ tiếp tục vòng lặp mà không thay đổi giá trị
                    """
                    for argument_index in range(1, len(gene["arguments"])):
                        if random.random() > self.pm:  # 变异概率
                            continue
                        if function_hash in individual.generator.interface.keys():
                            argument_type = individual.generator.interface[function_hash][argument_index - 1]
                            argument = individual.generator.get_random_argument(argument_type,
                                                                                function_hash,
                                                                                argument_index - 1)
                            gene["arguments"][argument_index] = argument
                        else:
                            for o_g in individual.other_generators:  # 跨合约的事务, 需要去别的generator里寻找
                                if function_hash in o_g.interface.keys():
                                    argument_type = o_g.interface[function_hash][argument_index - 1]
                                    argument = o_g.get_random_argument(argument_type,
                                                                       function_hash,
                                                                       argument_index - 1)
                                    gene["arguments"][argument_index] = argument

            
            """
            Đoạn mã này cập nhật các thuộc tính liên quan đến trạng thái khối (block state) và trạng thái toàn cục (global state) của gene
            Những thông tin này thường được sử dụng trong môi trường như blockchain để mô phỏng trạng thái thực tế của hệ thống"""
            # BLOCK
            if "timestamp" in gene:
                if random.random() <= self.pm:
                    gene["timestamp"] = individual.generator.get_random_timestamp(function_hash)
            else:
                gene["timestamp"] = individual.generator.get_random_timestamp(function_hash)

            if "blocknumber" in gene:
                if random.random() <= self.pm:
                    gene["blocknumber"] = individual.generator.get_random_blocknumber(function_hash)
            else:
                gene["blocknumber"] = individual.generator.get_random_blocknumber(function_hash)

            # GLOBAL STATE
            if "balance" in gene:
                if random.random() <= self.pm:
                    gene["balance"] = individual.generator.get_random_balance(function_hash)
            else:
                gene["balance"] = individual.generator.get_random_balance(function_hash)

            if "call_return" in gene:
                for address in gene["call_return"]:
                    if random.random() <= self.pm:
                        gene["call_return"][address] = individual.generator.get_random_callresult(function_hash, address)
            else:
                gene["call_return"] = dict()
                address, call_return_value = individual.generator.get_random_callresult_and_address(function_hash)
                if address and address not in gene["call_return"]:
                    gene["call_return"][address] = call_return_value

            if "extcodesize" in gene:
                for address in gene["extcodesize"]:
                    if random.random() <= self.pm:
                        gene["extcodesize"][address] = individual.generator.get_random_extcodesize(function_hash, address)
            else:
                gene["extcodesize"] = dict()
                address, extcodesize_value = individual.generator.get_random_extcodesize_and_address(function_hash)
                if address and address not in gene["extcodesize"]:
                    gene["extcodesize"][address] = extcodesize_value

            if "returndatasize" in gene:
                for address in gene["returndatasize"]:
                    if random.random() <= self.pm:
                        gene["returndatasize"][address] = individual.generator.get_random_returndatasize(function_hash, address)
            else:
                gene["returndatasize"] = dict()
                address, returndatasize_value = individual.generator.get_random_returndatasize_and_address(function_hash)
                if address and address not in gene["returndatasize"]:
                    gene["returndatasize"][address] = returndatasize_value

        individual.solution = individual.decode()
        return individual
