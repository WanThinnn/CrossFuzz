#!/usr/bin/env python3
# -*- coding: utf-8 -*-

class AssertionFailureDetector():
    '''
    Lớp này chịu trách nhiệm phát hiện lỗi khi câu lệnh assert thất bại trong hợp đồng thông minh.
    '''
    def __init__(self): # Hàm khởi tạo
        self.init()

    def init(self): # Hàm khởi tạo
        self.swc_id = 110 # Đặt ID tiêu chuẩn SWC (Smart Contract Weakness Classification) cho loại lỗ hổng này.
        self.severity = "Medium" # Đặt mức độ nghiêm trọng của lỗ hổng.

    def detect_assertion_failure(self, current_instruction, transaction_index): # Phương thức này chịu trách nhiệm kiểm tra xem có lỗi khi câu lệnh assert thất bại hay không.
        """
        Phát hiện lỗi assert trong lệnh hiện tại.
        Phương thức này kiểm tra xem lệnh hiện tại có phải là lỗi assert 
        (hoặc "ASSERTFAIL" hoặc "INVALID") hay không. Nếu có, nó sẽ trả về 
        chỉ số chương trình (pc) và chỉ số giao dịch.
        
        Tham số:
            current_instruction (dict): Lệnh hiện tại đang được thực thi. 
            Nó nên chứa một khóa "op" chỉ ra thao tác và một khóa "pc" 
            chỉ ra chỉ số chương trình.
            transaction_index (int): Chỉ số của giao dịch hiện tại.
        
        Trả về:
            tuple: Một bộ giá trị chứa chỉ số chương trình và chỉ số giao dịch 
            nếu phát hiện lỗi assert, nếu không thì (None, None).
        """
        
        if current_instruction["op"] in ["ASSERTFAIL", "INVALID"]: # Kiểm tra xem có lệnh ASSERTFAIL hoặc INVALID không.
            return current_instruction["pc"], transaction_index # Trả về chỉ số chương trình và chỉ số
        return None, None # Trả về giá trị None nếu không có lỗi khi câu lệnh assert thất bại.
