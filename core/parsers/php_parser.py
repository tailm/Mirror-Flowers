import ast
import subprocess
import tempfile
import os

class PHPParser:
    def parse(self, code: str):
        """
        解析PHP代码生成AST
        使用 php -l 进行语法检查
        """
        try:
            # 创建临时文件存储PHP代码
            with tempfile.NamedTemporaryFile(suffix='.php', mode='w', delete=False) as tmp:
                tmp.write(code)
                tmp_path = tmp.name

            # 使用 PHP 命令行进行语法检查
            result = subprocess.run(['php', '-l', tmp_path], 
                                 capture_output=True, 
                                 text=True)
            
            # 清理临时文件
            os.unlink(tmp_path)
            
            if "No syntax errors detected" not in result.stdout:
                raise Exception(result.stderr)
            
            # 这里可以添加更详细的AST分析
            # 目前先返回简单的语法检查结果
            return {
                "type": "php_file",
                "syntax_valid": True,
                "content": code
            }
            
        except subprocess.CalledProcessError as e:
            raise Exception(f"PHP解析错误: {str(e)}")
        except Exception as e:
            raise Exception(f"PHP解析错误: {str(e)}") 