#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from random import random, shuffle, choice
from itertools import accumulate
from bisect import bisect_right

from ...plugin_interfaces.operators.selection import Selection

'''
Đoạn mã này thực hiện phương pháp Linear Ranking Selection để chọn các cặp cha mẹ trong 
một thuật toán di truyền (genetic algorithm). Phương pháp này sử dụng một quy trình xếp hạng tuyến tính để lựa chọn 
các cá thể (individals) từ quần thể sao cho các cá thể có độ thích nghi cao có xác suất được chọn cao hơn
'''

class DataDependencyLinearRankingSelection(Selection):
    def __init__(self, env, pmin=0.1, pmax=0.9):
        self.env = env
        '''
        Selection operator using Linear Ranking selection method.

        Reference: Baker J E. Adaptive selection methods for genetic
        algorithms[C]//Proceedings of an International Conference on Genetic
        Algorithms and their applications. 1985: 101-111.
        '''
        # Selection probabilities for the worst and best individuals.
        self.pmin, self.pmax = pmin, pmax

    def select(self, population, fitness):
        '''
        Nhận vào quần thể (population) và hàm đánh giá độ thích nghi (fitness) và trả về cặp cha mẹ được chọn
        '''
        # Add rank to all individuals in population.
        all_fits = population.all_fits(fitness) # Tính toán độ thích nghi của tất cả cá thể trong quần thể
        indvs = population.individuals # Lấy ra tất cả cá thể trong quần thể
        sorted_indvs = sorted(indvs, key=lambda indv: all_fits[indvs.index(indv)])  # Các cá thể được sắp xếp theo độ thích nghi từ thấp đến cao

        NP = len(sorted_indvs)  # Số lượng cá thể trong quần thể

        # Tính toán xác suất chọn lọc cho từng cá thể dựa trên thứ hạng của chúng
        # NOTE: Here the rank i belongs to {1, ..., N}
        p = lambda i: (self.pmin + (self.pmax - self.pmin) * (i - 1) / (NP - 1))
        probabilities = [self.pmin] + [p(i) for i in range(2, NP)] + [self.pmax] # danh sách xác suất chọn lọc cho từng cá thể từ thấp dến cao

        # Chuẩn hóa xác suất chọn lọc
        psum = sum(probabilities) # Tổng xác suất chọn lọc
        wheel = list(accumulate([p / psum for p in probabilities]))  # Tạo vòng sau chọn lọc có tổng xác xuất bằng 1

        # Select parents.
        father_idx = bisect_right(wheel, random())  # Chọn ngẫu nhiên một vị trí trên vòng sau chọn lọc
        father = sorted_indvs[father_idx]   # Chọn cá thể tương ứng với vị trí trên vòng sau chọn lọc trong đanh sách sorted_indvs

        father_reads, father_writes = DataDependencyLinearRankingSelection.extract_reads_and_writes(father, self.env) # Lấy ra tập các đọc và ghi của cha
        f_a = [i["arguments"][0] for i in father.chromosome] 

        shuffle(indvs) # Xáo trộn quần thể
        for ind in indvs:
            i_a = [i["arguments"][0] for i in ind.chromosome]
            if f_a != i_a: # Kiểm tra xem cá thể cha có giống cá thể mẹ hoàn toàn hay không
                i_reads, i_writes = DataDependencyLinearRankingSelection.extract_reads_and_writes(ind, self.env)
                if not i_reads.isdisjoint(father_writes) or not father_reads.isdisjoint(i_writes): # Kiểm tra xem cha và mẹ tiềm năng có phụ thuộc dữ liệu hay không
                    return father, ind # Nếu không phụ thuộc dữ liệu trả về cặp cha và mẹ

        """
        Nếu sau khi duyệt hết các cá thể trong danh sách mà không tìm được mẹ phù hợp thì
        đoạn mã sẽ chọn cá thể mẹ theo cách đơn giản
        """
        mother_idx = (father_idx + 1) % len(wheel) #Lấy chỉ số mẹ mother_idx bằng cách chọn cá thể tiếp theo trong danh sách đã sắp xếp (theo thứ tự xác suất)
        mother = sorted_indvs[mother_idx] # Chọn cá thể mẹ tương ứng với chỉ số mother_idx

        return father, mother

    @staticmethod
    def extract_reads_and_writes(individual, env):
        reads, writes = set(), set()

        for t in individual.chromosome:
            _function_hash = t["arguments"][0]
            if _function_hash in env.data_dependencies:
                reads.update(env.data_dependencies[_function_hash]["read"])
                writes.update(env.data_dependencies[_function_hash]["write"])

        return reads, writes
