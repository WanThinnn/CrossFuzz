#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from z3 import BitVec
from utils.utils import convert_stack_value_to_int, convert_stack_value_to_hex

class IntegerOverflowDetector():

    '''
    Class này được sử dụng để phát hiện các lỗi tràn số nguyên (integer overflow) và tràn số nguyên âm (integer underflow) 
    trong quá trình thực thi mã lệnh. Nó kiểm tra các phép toán số học như cộng, trừ, nhân và xác định xem kết quả có 
    vượt quá giới hạn của kiểu dữ liệu số nguyên hay không.
    Attributes:
        swc_id (int): Mã nhận dạng của lỗi bảo mật.
        severity (str): Mức độ nghiêm trọng của lỗi.
        overflows (dict): Từ điển lưu trữ các lỗi tràn số nguyên.
        underflows (dict): Từ điển lưu trữ các lỗi tràn số nguyên âm.
        compiler_value_negation (bool): Cờ để xác định xem có sự phủ định giá trị của trình biên dịch hay không.
    Methods:
        __init__(): Khởi tạo đối tượng IntegerOverflowDetector.
        init(): Khởi tạo các thuộc tính của đối tượng.
        detect_integer_overflow(mfe, tainted_record, previous_instruction, current_instruction, individual, transaction_index): Phát hiện lỗi tràn số nguyên dựa trên các lệnh trước và sau trong quá trình thực thi.
    '''
    def __init__(self): # Hàm khởi tạo
        self.init()

    def init(self): # Hàm khởi tạo
        self.swc_id = 101 # Đặt ID tiêu chuẩn SWC (Smart Contract Weakness Classification) cho loại lỗ hổng này.
        self.severity = "High" # Đặt mức độ nghiêm trọng của lỗ hổng.
        self.overflows = {} # Khởi tạo lỗi tràn số nguyên
        self.underflows = {} # Khởi tạo lỗi tràn số nguyên âm
        self.compiler_value_negation = False # Khởi tạo cờ phủ định giá trị của trình biên dịch

    # Phương thức này chịu trách nhiệm phát hiện lỗi tràn số nguyên dựa trên các lệnh trước và sau trong quá trình thực thi.
    def detect_integer_overflow(self, mfe, tainted_record, previous_instruction, current_instruction, individual, transaction_index): 
        '''
        Phát hiện lỗi tràn số nguyên dựa trên các lệnh trước và sau trong quá trình thực thi.
        
        '''
        # Kiểm tra xem có lệnh trước đó không và có phải là lệnh NOT và lệnh ADD không.
        if previous_instruction and previous_instruction["op"] == "NOT" and current_instruction and current_instruction["op"] == "ADD":
            self.compiler_value_negation = True
        # Kiểm tra xem có lệnh trước đó không và có phải là lệnh ADD không.
        elif previous_instruction and previous_instruction["op"] == "ADD":
            a = convert_stack_value_to_int(previous_instruction["stack"][-2]) # Chuyển đổi giá trị stack[-2] thành số nguyên
            b = convert_stack_value_to_int(previous_instruction["stack"][-1]) # Chuyển đổi giá trị stack[-1] thành số nguyên
            # Kiểm tra xem tổng của a và b có bằng với giá trị stack cuối cùng không và không phải là phủ định giá trị của trình biên dịch.
            if a + b != convert_stack_value_to_int(current_instruction["stack"][-1]) and not self.compiler_value_negation:
                # Kiểm tra xem bản ghi bị nhiễm và stack có giá trị không.
                if tainted_record and tainted_record.stack and tainted_record.stack[-1]:
                    # Chuyển đổi giá trị stack[-1] thành số nguyên.
                    index = ''.join(str(taint) for taint in tainted_record.stack[-1])
                    # Kiểm tra xem có "calldataload" hoặc "callvalue" trong index không.
                    if "calldataload" in index or "callvalue" in index:
                        # Lưu trữ lỗi tràn số nguyên.
                        _function_hash = individual.chromosome[transaction_index]["arguments"][0]
                        _is_string = False # Khởi tạo cờ kiểm tra chuỗi
                        # Lặp qua các chỉ số của các đối số.
                        for _argument_index in [int(a.split("_")[-1]) for a in index.split() if a.startswith("calldataload_"+str(transaction_index)+"_")]:
                            # Kiểm tra xem đối số có phải là chuỗi không.
                            if individual.generator.interface[_function_hash][_argument_index] == "string":
                                _is_string = True # Nếu có, đặt cờ _is_string = True.
                        if not _is_string: # Nếu không phải là chuỗi.
                            self.overflows[index] = previous_instruction["pc"], transaction_index # Lưu trữ lỗi tràn số nguyên.
        # Kiểm tra xem có lệnh trước đó không và có phải là lệnh MUL không.
        elif previous_instruction and previous_instruction["op"] == "MUL":
            a = convert_stack_value_to_int(previous_instruction["stack"][-2]) 
            b = convert_stack_value_to_int(previous_instruction["stack"][-1]) 
            if a * b != convert_stack_value_to_int(current_instruction["stack"][-1]):
                if tainted_record and tainted_record.stack and tainted_record.stack[-1]: # Kiểm tra xem bản ghi bị nhiễm và stack có giá trị không.
                    index = ''.join(str(taint) for taint in tainted_record.stack[-1]) # Chuyển đổi giá trị stack[-1] thành chuỗi.
                    if "calldataload" in index or "callvalue" in index: # Kiểm tra xem có "calldataload" hoặc "callvalue" trong index không.
                        self.overflows[index] = previous_instruction["pc"], transaction_index # Lưu trữ lỗi tràn số nguyên.
        # Kiểm tra xem có lệnh trước đó không và có phải là lệnh SUB không.
        elif previous_instruction and previous_instruction["op"] == "SUB":
            a = convert_stack_value_to_int(previous_instruction["stack"][-1])
            b = convert_stack_value_to_int(previous_instruction["stack"][-2]) 
            if a - b != convert_stack_value_to_int(current_instruction["stack"][-1]):
                if tainted_record and tainted_record.stack and tainted_record.stack[-1]: 
                    index = ''.join(str(taint) for taint in tainted_record.stack[-1]) 
                    self.underflows[index] = previous_instruction["pc"], transaction_index
                else: # Nếu không có bản ghi bị nhiễm.
                    tainted_record = mfe.symbolic_taint_analyzer.get_tainted_record(index=-1) 
                    if tainted_record: # Kiểm tra xem bản ghi bị nhiễm có giá trị không.
                        tainted_record.stack[-2] = [BitVec("_".join(["underflow", hex(previous_instruction["pc"])]), 256)] 
                        index = ''.join(str(taint) for taint in tainted_record.stack[-2]) 
                        self.underflows[index] = previous_instruction["pc"], transaction_index
        
        # Kiểm tra xem có lệnh trước đó không và có phải là lệnh DIV không.
        if current_instruction and current_instruction["op"] == "SSTORE": 
            if tainted_record and tainted_record.stack and tainted_record.stack[-2]: 
                index = ''.join(str(taint) for taint in tainted_record.stack[-2]) 
                if index in self.overflows: 
                    return self.overflows[index][0], self.overflows[index][1], "overflow"
                if index in self.underflows: 
                    return self.underflows[index][0], self.underflows[index][1], "underflow" 
        
        # Kiểm tra xem có lệnh trước đó không và có phải là lệnh CALL không.
        elif current_instruction and current_instruction["op"] == "CALL":
            if tainted_record and tainted_record.stack and tainted_record.stack[-3]: # Call value
                index = ''.join(str(taint) for taint in tainted_record.stack[-3])
                if index in self.overflows:
                    return self.overflows[index][0], self.overflows[index][1], "overflow"
                if index in self.underflows:
                    return self.underflows[index][0], self.underflows[index][1], "underflow"
        
        # Kiểm tra xem có lệnh trước đó không và có phải là lệnh LT, GT, SLT, SGT, EQ không.
        elif current_instruction and current_instruction["op"] in ["LT", "GT", "SLT", "SGT", "EQ"]:
            if tainted_record and tainted_record.stack:
                if tainted_record.stack[-1]: # First operand
                    index = ''.join(str(taint) for taint in tainted_record.stack[-1])
                    if index in self.overflows:
                        return self.overflows[index][0], self.overflows[index][1], "overflow"
                    if index in self.underflows:
                        return self.underflows[index][0], self.underflows[index][1], "underflow"
                if tainted_record.stack[-2]: # Second operand
                    index = ''.join(str(taint) for taint in tainted_record.stack[-2])
                    if index in self.overflows:
                        return self.overflows[index][0], self.overflows[index][1], "overflow"
                    if index in self.underflows:
                        return self.underflows[index][0], self.underflows[index][1], "underflow"
        return None, None, None # Trả về giá trị None nếu không có lỗi tràn số nguyên.
