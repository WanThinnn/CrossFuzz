#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from random import random, shuffle, choice
from itertools import accumulate
from bisect import bisect_right

from ...plugin_interfaces.operators.selection import Selection
"""
Đoạn mã triển khai thuật toán Linear Ranking Selection, một phương pháp được sử dụng trong các thuật toán 
di truyền (Genetic Algorithms - GA) để chọn các cặp cha mẹ cho quá trình tái tổ hợp (recombination)
Thuật toán này đảm bảo rằng các cá thể tốt hơn (theo giá trị fitness) có xác suất được chọn cao hơn, 
nhưng vẫn giữ một cơ hội cho các cá thể yếu hơn được chọn, giúp duy trì đa dạng trong quần thể
"""
class LinearRankingSelection(Selection):
    def __init__(self, pmin=0.1, pmax=0.9):
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
        Select a pair of parent individuals using linear ranking method.
        '''

        # Add rank to all individuals in population.
        all_fits = population.all_fits(fitness) # Tính giá trị thích nghi của các cá thể trong quần thể
        indvs = population.individuals # Lấy ra danh sách các cá thể trong quần thể
        sorted_indvs = sorted(indvs, key=lambda indv: all_fits[indvs.index(indv)]) # Sắp xếp các cá thể theo thứ tự tăng dần của giá trị fitness

        # Số lượng cá thể trong quần thể
        NP = len(population)

        # Tính toán xác suất chọn lọc cho từng cá thể dựa trên thứ hạng của chúng
        # NOTE: Sắp xếp theo 1 - > n tương đương từ min -> max
        p = lambda i: (self.pmin + (self.pmax - self.pmin)*(i-1)/(NP-1))
        probabilities = [self.pmin] + [p(i) for i in range(2, NP)] + [self.pmax] #Tính toán xác suất chọn lọc cho từng cá thể dựa trên thứ hạng của chúng

        # Chuẩn hóa xác suất chọn lọc
        psum = sum(probabilities) # Tổng xác suất chọn lọc
        wheel = list(accumulate([p/psum for p in probabilities])) # Tạo vòng sau chọn lọc có tổng xác xuất bằng 1

        # Select parents.
        father_idx = bisect_right(wheel, random())# Chọn ngẫu nhiên một vị trí trên vòng sau chọn lọc
        father = sorted_indvs[father_idx] # Chọn cá thể tương ứng với vị trí trên vòng sau chọn lọc trong đanh sách sorted_indvs
        mother_idx = (father_idx + 1) % len(wheel) #Lấy chỉ số mẹ mother_idx bằng cách chọn cá thể tiếp theo của cá thể cha trong danh sách đã sắp xếp (theo thứ tự xác suất)
        mother = sorted_indvs[mother_idx] # Chọn cá thể mẹ tương ứng với chỉ số mother_idx

        return father, mother # Trả về cặp cha mẹ được chọn
