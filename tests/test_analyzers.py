import unittest
from pathlib import Path
from core.analyzers.context_analyzer import ContextAnalyzer
from code_analyzer import AnalyzerConfig

class TestContextAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = ContextAnalyzer(AnalyzerConfig())
        
    def test_analyze_file(self):
        test_file = Path(__file__).parent / 'test_data' / 'simple.py'
        self.analyzer.analyze_project_context([test_file])
        context = self.analyzer.get_file_context(str(test_file))
        self.assertIsNotNone(context)
        
    def tearDown(self):
        self.analyzer.clear_analysis()

if __name__ == '__main__':
    unittest.main() 