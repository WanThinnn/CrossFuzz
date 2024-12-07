#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import inspect
from functools import wraps

from ..components.individual import Individual
from ..components.population import Population
'''
chứa các metaclass được thiết kế để kiểm soát cấu trúc và hành vi của các lớp liên quan đến 
phân tích, lai ghép (crossover), đột biến (mutation), và lựa chọn (selection) trong một hệ thống giả lập 
thuật toán tiến hóa
'''
class AnalysisMeta(type):
    '''
    Đảm bảo các lớp phân tích có các phương thức bắt buộc và đúng định dạng
    '''
    def __new__(cls, name, bases, attrs):
        # Check interval type.
        if 'interval' in attrs: #Kiểm tra xem thuộc tính interval (nếu có) phải là số nguyên dương. Nếu không, ném lỗi TypeError
            interval = attrs['interval']
            if type(interval) is not int or interval <= 0:
                raise TypeError('analysis interval must be a positive integer')

        for method_name in ['setup', 'register_step', 'finalize']: #Kiểm tra xem các phương thức setup, register_step, finalize có được triển khai hay không
            method = attrs.get(method_name, None)
            if method is not None and not callable(method): #Đảm bảo rằng các phương thức setup, register_step, finalize nếu được định nghĩa thì nó phải có thể được gọi
                msg = "{} must be a callable object".format(method)
                raise AttributeError(msg)
            # Set default interface methods.
            elif method is None: #Nếu không có phương thức nào được triển khai, thì sẽ tạo ra các phương thức mặc định
                if method_name == 'setup':
                    attrs[method_name] = lambda self, ng, engine: None
                elif method_name == 'register_step':
                    attrs[method_name] = lambda self, g, population, engine: None
                elif method_name == 'finalize':
                    attrs[method_name] = lambda self, population, engine: None

        # Set logger.
        logger_name = 'engine.{}'.format(name) #Tạo tên logger cho lớp phân tích
        attrs['logger'] = logging.getLogger(logger_name)

        return type.__new__(cls, name, bases, attrs)


class CrossoverMeta(type):
    '''
    Quản lý các lớp xử lý phép lai ghép trong thuật toán tiến hóa
    '''
    def __new__(cls, name, bases, attrs):
        if 'cross' not in attrs: #Xác minh sự tồn tại của phương thức cross. Nếu thiếu, ném lỗi AttributeError
            raise AttributeError('crossover operator class must have cross method')

        if 'pc' in attrs and (attrs['pc'] <= 0.0 or attrs['pc'] > 1.0): #Kiểm tra giá trị pc (xác suất lai ghép), đảm bảo nằm trong khoảng (0.0, 1.0]. Nếu không, ném lỗi ValueError
            raise ValueError('Invalid crossover probability')

        cross = attrs['cross'] 

        # Kiểm tra đảm bảo có đủ 2 tham số bắt buộc là bố và mẹ
        sig = inspect.signature(cross)
        if 'father' not in sig.parameters:
            raise NameError('cross method must have father parameter')
        if 'mother' not in sig.parameters:
            raise NameError('cross method must have mother parameter')

        # Add parameter check to user-defined method.
        @wraps(cross)
        def _wrapped_cross(self, father, mother):
            '''
            Kiểm thử dữ liệu:
                father phải là đối tượng thuộc lớp Individualfather phải là đối tượng thuộc lớp Individual
                mother phải là Individual hoặc None
            '''
            if not (isinstance(father, Individual) and (isinstance(mother, Individual) or mother is None)):
                raise TypeError('father and mother\'s type must be Individual or a subclass of Individual')

            return cross(self, father, mother)

        attrs['cross'] = _wrapped_cross

        # Set logger.
        logger_name = 'engine.{}'.format(name)
        attrs['logger'] = logging.getLogger(logger_name) #tạo logger riêng cho lớp lai ghép

        return type.__new__(cls, name, bases, attrs)


class MutationMeta(type):
    '''
    Quản lý các lớp thực hiện phép đột biến
    '''
    def __new__(cls, name, bases, attrs):
        if 'mutate' not in attrs: #Xác minh sự tồn tại của phương thức mutate. Nếu thiếu, ném lỗi AttributeError
            raise AttributeError('mutation operator class must have mutate method')

        if 'pm' in attrs and (attrs['pm'] <= 0.0 or attrs['pm'] > 1.0): #Kiểm tra giá trị pm (xác suất đột biến), đảm bảo nằm trong khoảng (0.0, 1.0]. Nếu không, ném lỗi ValueError
            raise ValueError('Invalid mutation probability')

        mutate = attrs['mutate']

        # Check parameters of mutate method.
        sig = inspect.signature(mutate)
        if 'individual' not in sig.parameters: #kiểm tra tham số của phương thức mutate, đảm bảo có tham số bắt buộc individual
            raise NameError('mutate method must have individual parameter')

        # Add parameter check to user-defined method.
        @wraps(mutate)
        def _wrapped_mutate(self, individual, engine):
            ''' Wrapper to add parameters type checking.
            '''
            # Check parameter types.
            if not isinstance(individual, Individual): #individual phải là đối tượng thuộc lớp Individual
                raise TypeError('individual\' type must be Individual or a subclass of Individual')

            return mutate(self, individual, engine)

        attrs['mutate'] = _wrapped_mutate

        # Set logger.
        logger_name = 'engine.{}'.format(name)
        attrs['logger'] = logging.getLogger(logger_name) #tạo logger riêng cho lớp đột biến

        return type.__new__(cls, name, bases, attrs)


class SelectionMeta(type):
    '''
    Quản lý các lớp xử lý việc chọn lọc
    '''
    def __new__(cls, name, bases, attrs):
        # Check select method.
        if 'select' not in attrs: #Xác minh sự tồn tại của phương thức select. Nếu thiếu, ném lỗi AttributeError
            raise AttributeError('selection operator class must have select method')

        select = attrs['select']

        # Check select arguments.
        sig = inspect.signature(select)
        if 'population' not in sig.parameters: #Kiểm tra tham số của phương thức select, đảm bảo có tham số bắt buộc population
            raise NameError('select method must have population parameter')

        # Add parameter check to user-defined method.
        @wraps(select)
        def _wrapped_select(self, population, fitness):
            ''' Wrapper to add parameters type checking.
            '''
            # Check parameter types.
            if not isinstance(population, Population): #population phải là đối tượng thuộc lớp Population
                raise TypeError('population must be Population object')

            return select(self, population, fitness)

        attrs['select'] = _wrapped_select

        # Set logger.
        logger_name = 'engine.{}'.format(name)
        attrs['logger'] = logging.getLogger(logger_name) #tạo logger riêng cho lớp chọn lọc

        return type.__new__(cls, name, bases, attrs)
