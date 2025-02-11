from core.analyzers.context_analyzer import ContextAnalyzer
from code_analyzer import AnalyzerConfig

def analyze_single_file():
    """单文件分析示例"""
    config = AnalyzerConfig()
    analyzer = ContextAnalyzer(config)
    
    # 分析单个文件
    analyzer.analyze_project_context(['example.py'])
    
    # 获取分析结果
    context = analyzer.get_file_context('example.py')
    print("文件分析结果:", context)
    
    # 获取函数调用图
    call_graph = analyzer.get_call_graph('main')
    print("函数调用图:", call_graph)
    
    # 清理
    analyzer.clear_analysis()

if __name__ == '__main__':
    analyze_single_file() 