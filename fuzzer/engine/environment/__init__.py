#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Định nghĩa một lớp FuzzingEnvironment, lớp này tạo ra một môi trường để quản lý 
và theo dõi các dữ liệu liên quan đến quá trình fuzz testing trong môi trường hợp đồng thông minh
'''

class FuzzingEnvironment:
    def __init__(self, **kwargs) -> None:
        self.nr_of_transactions = 0 # Số lượng giao dịch
        self.unique_individuals = set() # Tập hợp các cá thể duy nhất
        self.code_coverage = set() # Tập hợp mã đã được phủ (coverage).
        self.children_code_coverage = dict() # Tập hợp mã đã được phủ của các cá thể con.
        self.previous_code_coverage_length = 0 # Độ dài của mã đã được phủ trước đó.

        self.visited_branches = dict() # Tập hợp các nhánh đã được thăm.

        self.memoized_fitness = dict() # Tập hợp các giá trị fitness đã được lưu trữ.
        self.memoized_storage = dict() # Tập hợp các giá trị storage đã được lưu trữ.
        self.memoized_symbolic_execution = dict() # Các dữ liệu đã được ghi nhớ để tối ưu hóa quá trình tính toán.

        self.individual_branches = dict() # Tập hợp các nhánh của từng cá thể.

        self.data_dependencies = dict() # Tập hợp các phụ thuộc dữ liệu.

        self.__dict__.update(kwargs) 
