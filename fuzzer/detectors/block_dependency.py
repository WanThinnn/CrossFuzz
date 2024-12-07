#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from utils.utils import convert_stack_value_to_int

class BlockDependencyDetector():
    '''
    Phát hiện phụ thuộc vào thông tin của khối (block). Các Bước Chính:
    1. Kiểm tra các lệnh gọi hàm và các lệnh đặc biệt liên quan đến khối.
    2. Kiểm tra các biểu thức từ các nhánh trước đó để tìm các yếu tố liên quan đến khối.
    3. Kiểm tra các lệnh so sánh trong ngữ cảnh bị nhiễm dữ liệu.
    4. Đăng ký các lệnh trực tiếp liên quan đến thông tin khối.
    5. Kiểm tra và xác định khi nào thực thi dừng lại nếu có phụ thuộc khối.

    '''
    def __init__(self): # Hàm khởi tạo
        self.init()

    def init(self): # Hàm khởi tạo
        self.swc_id = 120 # Đặt ID tiêu chuẩn SWC (Smart Contract Weakness Classification) cho loại lỗ hổng này.
        self.severity = "Low" # Đặt mức độ nghiêm trọng của lỗ hổng.
        self.block_instruction = None # Khởi tạo chỉ số chương trình
        self.block_dependency = False # Khởi tạo phụ thuộc vào khối

    def detect_block_dependency(self, tainted_record, current_instruction, previous_branch, transaction_index): # Phương thức này chịu trách nhiệm kiểm tra xem có phụ thuộc vào thông tin của khối hay không.
        """
        Phát hiện xem lệnh hiện tại có phụ thuộc vào thông tin liên quan đến khối hay không.

        Phương thức này phân tích lệnh hiện tại và ngữ cảnh của nó để xác định xem có phụ thuộc vào dữ liệu đặc thù của blockchain như `blockhash`, `coinbase`, `timestamp`, `number`,
        `difficulty`, hoặc `gaslimit` hay không. Nó kiểm tra các cuộc gọi hàm và các thao tác cụ thể có thể chỉ ra các phụ thuộc như vậy bằng cách xem xét loại hoạt động của lệnh và các biểu thức liên quan trong nhánh trước hoặc ngăn xếp của bản ghi bị nhiễm. Nếu một phụ thuộc khối được phát hiện, nó sẽ đặt cờ `block_dependency` và ghi lại lệnh liên quan đến khối và chỉ số giao dịch.
        
        Tham số:
            tainted_record (TaintedRecord): Bản ghi bị nhiễm chứa thông tin ngăn xếp.
            current_instruction (dict): Lệnh hiện tại đang được phân tích.
            previous_branch (list): Danh sách các biểu thức từ nhánh trước để kiểm tra các phụ thuộc khối.
            transaction_index (int): Chỉ số của giao dịch hiện tại.
        
        Trả về:
            tuple: Một tuple chứa thông tin lệnh liên quan đến khối (bộ đếm chương trình và chỉ số giao dịch)
                   nếu một phụ thuộc khối được phát hiện và lệnh hiện tại là một thao tác dừng; nếu không, (None, None).
        """
        # Kiểm tra xem có lệnh gọi hàm nào không và có phải là lệnh gọi hàm không.
        if current_instruction["op"] == "CALL" and (convert_stack_value_to_int(current_instruction["stack"][-3]) or tainted_record and tainted_record.stack[-3]) or \
           current_instruction["op"] in ["STATICCALL", "SELFDESTRUCT", "SUICIDE", "CREATE", "DELEGATECALL"]:
            # Lặp qua các biểu thức từ nhánh trước đó để kiểm tra xem có chứa các từ khóa liên quan đến khối như `blockhash`, `coinbase`, `timestamp`, `number`, `difficulty`, `gaslimit`.
            for expression in previous_branch: # 
                if "blockhash" in str(expression) or \
                   "coinbase" in str(expression) or \
                   "timestamp" in str(expression) or \
                   "number" in str(expression) or \
                   "difficulty" in str(expression) or \
                   "gaslimit" in str(expression):
                   self.block_dependency = True # Nếu có, đặt `self.block_dependency = True`.
        # Nếu lệnh hiện tại là một lệnh so sánh như `LT`, `GT`, `SLT`, `SGT`, `EQ`, kiểm tra các giá trị trên stack để xác định phụ thuộc khối.
        elif current_instruction and current_instruction["op"] in ["LT", "GT", "SLT", "SGT", "EQ"]:
            # Kiểm tra xem có bản ghi bị nhiễm (`tainted_record`) và stack không rỗng.
            if tainted_record and tainted_record.stack: # Nếu có, lặp qua các biểu thức trên stack để kiểm tra xem có phụ thuộc khối không.
                if tainted_record.stack[-1]: # Kiểm tra stack[-1]
                    for expression in tainted_record.stack[-1]: # Lặp qua các biểu thức trên stack[-1]
                        if "blockhash" in str(expression) or \
                           "coinbase" in str(expression) or \
                           "timestamp" in str(expression) or \
                           "number" in str(expression) or \
                           "difficulty" in str(expression) or \
                           "gaslimit" in str(expression): # Nếu có, đặt `self.block_dependency = True`.
                           self.block_dependency = True
                if tainted_record.stack[-2]: # Kiểm tra stack[-2]
                    for expression in tainted_record.stack[-2]: # Lặp qua các biểu thức trên stack[-2]
                        if "blockhash" in str(expression) or \
                           "coinbase" in str(expression) or \
                           "timestamp" in str(expression) or \
                           "number" in str(expression) or \
                           "difficulty" in str(expression) or \
                           "gaslimit" in str(expression): # Nếu có, đặt `self.block_dependency = True`.
                           self.block_dependency = True
        # Đăng ký thông tin liên quan đến khối
        elif current_instruction["op"] in ["BLOCKHASH", "COINBASE", "TIMESTAMP", "NUMBER", "DIFFICULTY", "GASLIMIT"]:
            self.block_instruction = current_instruction["pc"], transaction_index
        # Nếu lệnh hiện tại là một lệnh dừng như `STOP`, `SELFDESTRUCT`, `RETURN`, kiểm tra xem có phụ thuộc khối không.
        if self.block_dependency and current_instruction["op"] in ["STOP", "SELFDESTRUCT", "RETURN"]:
            return self.block_instruction # Trả về thông tin lệnh liên quan đến khối
        return None, None # Nếu không, trả về None
