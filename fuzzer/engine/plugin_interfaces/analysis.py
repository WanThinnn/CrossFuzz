#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .metaclasses import AnalysisMeta


class OnTheFlyAnalysis(metaclass=AnalysisMeta):
    '''
    Cung cấp một giao diện (interface) để dễ dàng mở rộng và 
    tùy chỉnh hành vi của phân tích trong thời gian thực (on-the-fly) khi thuật toán di truyền đang chạy

    Dùng làm cơ sở (base class) cho các lớp phân tích tùy chỉnh khác, buộc người lập trình 
    phải triển khai các phương thức cần thiết (setup, register_step, finalize)
    '''
    # Only used in master process?
    master_only = False # True nếu chỉ chạy trên tiến trình chính (master process)

    # Analysis interval.
    interval = 1 #tần suất phân tích (số thế hệ giữa các lần gọi register_step)

    def setup(self, ng, engine):
        '''
        Được gọi ngay trước khi thuật toán chính bắt đầu
        Cho phép cấu hình đối tượng phân tích tùy theo số thế hệ (ng) và cấu trúc của GA Engine (engine)
        Phải được ghi đè (override) trong lớp con
        '''
        raise NotImplementedError

    def register_step(self, g, population, engine):
        '''
        Được gọi trong mỗi bước lặp (generation) của thuật toán
        Cho phép phân tích dữ liệu của quần thể hiện tại
        Phải được ghi đè trong lớp con
        '''
        raise NotImplementedError

    def finalize(self, population, engine):
        '''
        Được gọi sau khi thuật toán hoàn tất

        Dùng để xử lý hậu kỳ, tổng hợp dữ liệu phân tích và/hoặc lưu kết quả

        Phải được ghi đè trong lớp con.
        '''
        raise NotImplementedError #Đảm bảo rằng bất kỳ lớp nào kế thừa từ OnTheFlyAnalysis cũng phải triển khai các phương thức này

