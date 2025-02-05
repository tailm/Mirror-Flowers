import javalang

class JavaParser:
    def parse(self, code: str):
        """
        解析Java代码生成AST
        """
        try:
            ast = javalang.parse.parse(code)
            return ast
        except Exception as e:
            raise Exception(f"Java解析错误: {str(e)}") 