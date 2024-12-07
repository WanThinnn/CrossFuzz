#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from z3 import is_expr
from z3.z3util import get_vars


class ArbitraryMemoryAccessDetector():
    '''
    Phát hiện truy cập bộ nhớ tùy ý.
    '''
    def __init__(self): #Hàm khởi tạo
        self.init()

    def init(self): # Hàm khởi tạo
        self.swc_id = 124 #Đặt ID tiêu chuẩn SWC (Smart Contract Weakness Classification) cho loại lỗ hổng này.
        self.severity = "High"#Đặt mức độ nghiêm trọng của lỗ hổng.

    def detect_arbitrary_memory_access(self, tainted_record, individual, current_instruction, transaction_index):
        '''
        Phương thức này chịu trách nhiệm kiểm tra xem có truy cập bộ nhớ tùy ý xảy ra trong một giao dịch hay không. Dưới code có phân tích các bước chi tiết.
        '''
        if current_instruction["op"] == "SSTORE": #Kiểm tra xem có lệnh SSTORE nào không. Đây là bước đầu để xác định có thể xảy ra truy cập bộ nhớ tùy ý.
            if tainted_record and tainted_record.stack: #Kiểm tra xem có bản ghi nhiễm độc và ngăn xếp không.
                tainted_index = tainted_record.stack[-1] #Lấy chỉ số nhiễm độc
                tainted_value = tainted_record.stack[-2] #Lấy giá tr
                if tainted_index and tainted_value and is_expr(tainted_index[0]) and is_expr(tainted_value[0]): #Kiểm tra xem có chỉ số và giá trị nhiễm độc không.
                    if get_vars(tainted_index[0]) and get_vars(tainted_value[0]): #     Kiểm tra x
                        tainted_index_var = get_vars(tainted_index[0])[0] #Lấy biến nhiễm độc
                        tainted_value_var = get_vars(tainted_value[0])[0] #Lấy biến nhiễm độc
                        if tainted_index != tainted_value and "calldataload_" in str(tainted_index[0]) and "calldataload_" in str(tainted_value[0]): #Kiểm tra xem chỉ số và giá trị nhiễm độc có phải là calldataload không.
                            if len(str(tainted_index_var).split("_")) == 3: #Kiểm tra xem chỉ số nhiễm độc có phải là calldataload không.
                                transaction_index = int(str(tainted_index_var).split("_")[1]) #Lấy chỉ số
                                argument_index = int(str(tainted_index_var).split("_")[2]) + 1 #Lấy chỉ số
                                if type(individual.chromosome[transaction_index]["arguments"][argument_index]) is int and individual.chromosome[transaction_index]["arguments"][argument_index] > 2 ** 128 - 1: #Kiểm tra xem giá trị nhiễm độc có lớn hơn 2^128 - 1 không.
                                    return current_instruction["pc"], transaction_index # Trả về chỉ số chương trình và chỉ số
        return None, None #Trả về giá trị None nếu không có truy cập bộ nhớ tùy ý.
