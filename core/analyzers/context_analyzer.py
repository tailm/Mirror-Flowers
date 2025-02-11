from code_analyzer import CodeAnalyzer
from typing import Dict, Set, List, Any, Optional, Union
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import logging
from functools import lru_cache
from tqdm import tqdm
import json
from code_analyzer import AnalyzerConfig

logger = logging.getLogger(__name__)

class ContextAnalyzer:
    def __init__(self, config: Optional[AnalyzerConfig] = None):
        self.code_analyzer = CodeAnalyzer(config)
        self._cache: Dict[str, bool] = {}  # 缓存分析结果
        
    def analyze_project_context(self, files: List[Union[str, Path]]) -> None:
        """分析项目整体上下文
        
        Args:
            files: 要分析的文件路径列表
            
        Example:
            analyzer = ContextAnalyzer()
            analyzer.analyze_project_context(['file1.py', 'file2.py'])
        """
        with ThreadPoolExecutor(max_workers=self.code_analyzer.config.max_workers) as executor:
            list(tqdm(
                executor.map(self._analyze_file_context, files),
                total=len(files),
                desc="分析项目文件"
            ))
            
    def _analyze_file_context(self, file_path: Union[str, Path]) -> None:
        """分析单个文件的上下文"""
        try:
            # 检查缓存
            if file_path in self._cache:
                return
            
            # 检查文件是否存在
            if not Path(file_path).exists():
                raise FileNotFoundError(f"文件不存在: {file_path}")
            
            # 检查文件是否是 Python 文件
            if not str(file_path).endswith('.py'):
                raise ValueError(f"不是 Python 文件: {file_path}")
            
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            self.code_analyzer.analyze_file(content, file_path)
            self._cache[file_path] = True
        
        except (UnicodeDecodeError, FileNotFoundError, ValueError) as e:
            logger.error(f"分析文件失败 {file_path}: {str(e)}")
        except Exception as e:
            logger.exception(f"未知错误 {file_path}: {str(e)}")
        
    @lru_cache(maxsize=128)
    def get_call_graph(self, function_name: str) -> Dict[str, Any]:
        """获取函数调用图
        
        Args:
            function_name: 要分析的函数名
            
        Returns:
            包含函数调用关系的字典，格式为:
            {
                'name': 函数名,
                'calls': 该函数调用的其他函数集合,
                'called_by': 调用该函数的其他函数集合
            }
        """
        calls = self.code_analyzer.get_function_calls(function_name)
        called_by = set()
        
        # 查找调用该函数的其他函数
        for caller, callees in self.code_analyzer.function_calls.items():
            if function_name in callees:
                called_by.add(caller)
                
        return {
            'name': function_name,
            'calls': calls,
            'called_by': called_by
        }
        
    @lru_cache(maxsize=128)
    def get_variable_scope(self, variable_name: str) -> Optional[Dict[str, Any]]:
        """获取变量作用域"""
        # 在所有文件中查找该变量的定义
        defined_in = set()
        for file_path, globals_set in self.code_analyzer.globals.items():
            if variable_name in globals_set:
                defined_in.add(file_path)
        
        if defined_in:
            # 获取变量的使用信息
            usage_info = self._find_variable_usage(variable_name)
            return {
                'type': 'global',
                'defined_in': list(defined_in),
                'used_in': usage_info
            }
        return None

    def _find_variable_usage(self, variable_name: str) -> Dict[str, Any]:
        """查找变量的使用位置"""
        usages = self.code_analyzer.get_variable_usages(variable_name)
        
        # 将使用位置按文件分组
        usage_by_file = {}
        for usage in usages:
            if ':' in usage:
                file_path, function_name = usage.split(':', 1)
                usage_by_file.setdefault(file_path, set()).add(function_name)
            else:
                # 模块级别的使用
                usage_by_file.setdefault(usage, set()).add('module_level')
        
        return {
            'files': list(usage_by_file.keys()),
            'details': {
                file_path: {
                    'module_level': 'module_level' in functions,
                    'functions': [f for f in functions if f != 'module_level']
                }
                for file_path, functions in usage_by_file.items()
            }
        }

    def get_file_context(self, file_path: str) -> dict:
        """获取文件的完整上下文信息"""
        return {
            'code_analysis': self.code_analyzer.get_file_analysis(file_path)
        }

    def get_project_analysis(self) -> dict:
        """获取项目整体分析结果"""
        return {
            'all_dependencies': self.code_analyzer.dependencies,
            'all_globals': self.code_analyzer.globals,
            'function_call_graph': self.code_analyzer.function_calls,
            'class_hierarchy_graph': self.code_analyzer.class_hierarchy,
            'variable_usage_map': self.code_analyzer.variable_usages
        }

    def clear_cache(self):
        """清除缓存"""
        self._cache.clear()

    def validate_analysis(self) -> List[str]:
        """验证分析结果的完整性和一致性
        
        Returns:
            发现的问题列表
        """
        issues = []
        
        # 检查函数调用的一致性
        for caller, callees in self.code_analyzer.function_calls.items():
            if ':' not in caller:
                issues.append(f"无效的调用者格式: {caller}")
            
        # 检查类继承的有效性
        for class_name, bases in self.code_analyzer.class_hierarchy.items():
            if ':' not in class_name:
                issues.append(f"无效的类名格式: {class_name}")
            
        # 检查变量使用的有效性
        for var_name, usages in self.code_analyzer.variable_usages.items():
            for usage in usages:
                if ':' not in usage and not usage.endswith('.py'):
                    issues.append(f"无效的变量使用位置: {usage}")
                
        return issues 

    def clear_analysis(self) -> None:
        """清理所有分析结果"""
        self._cache.clear()
        self.code_analyzer.dependencies.clear()
        self.code_analyzer.globals.clear()
        self.code_analyzer.function_calls.clear()
        self.code_analyzer.class_hierarchy.clear()
        self.code_analyzer.variable_usages.clear()

    def save_analysis(self, output_path: Union[str, Path]) -> None:
        """保存分析结果到文件"""
        result = {
            'dependencies': {k: list(v) for k, v in self.code_analyzer.dependencies.items()},
            'globals': {k: list(v) for k, v in self.code_analyzer.globals.items()},
            'function_calls': {k: list(v) for k, v in self.code_analyzer.function_calls.items()},
            'class_hierarchy': self.code_analyzer.class_hierarchy,
            'variable_usages': {k: list(v) for k, v in self.code_analyzer.variable_usages.items()}
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2)
            
    def load_analysis(self, input_path: Union[str, Path]) -> None:
        """从文件加载分析结果"""
        with open(input_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        self.code_analyzer.dependencies = {k: set(v) for k, v in data['dependencies'].items()}
        self.code_analyzer.globals = {k: set(v) for k, v in data['globals'].items()}
        self.code_analyzer.function_calls = {k: set(v) for k, v in data['function_calls'].items()}
        self.code_analyzer.class_hierarchy = data['class_hierarchy']
        self.code_analyzer.variable_usages = {k: set(v) for k, v in data['variable_usages'].items()} 

    def get_analysis_stats(self) -> Dict[str, Any]:
        """获取分析结果的统计信息"""
        return {
            'total_files': len(self.code_analyzer.dependencies),
            'total_functions': len({
                func.split(':')[1] 
                for func in self.code_analyzer.function_calls.keys()
            }),
            'total_classes': len(self.code_analyzer.class_hierarchy),
            'total_globals': sum(len(vars) for vars in self.code_analyzer.globals.values()),
            'dependencies_stats': {
                'total': sum(len(deps) for deps in self.code_analyzer.dependencies.values()),
                'by_file': {
                    file: len(deps) 
                    for file, deps in self.code_analyzer.dependencies.items()
                }
            }
        } 