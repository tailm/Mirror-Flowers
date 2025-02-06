import json

class DependencyAnalyzer:
    def __init__(self):
        self.vulnerability_database = self._load_vulnerability_database()
        self.dependency_graph = {}
        
    def analyze_dependencies(self, project_files):
        """完整的项目依赖分析"""
        issues = []
        for file in project_files:
            if file.endswith('pom.xml'):
                issues.extend(self._analyze_maven_dependencies(file))
            elif file.endswith('package.json'):
                issues.extend(self._analyze_npm_dependencies(file))
            elif file.endswith('requirements.txt'):
                issues.extend(self._analyze_python_dependencies(file))
            elif file.endswith('composer.json'):
                issues.extend(self._analyze_composer_dependencies(file))
        return issues

    def _analyze_maven_dependencies(self, pom_file):
        """分析Maven依赖"""
        try:
            with open(pom_file, 'r') as f:
                content = f.read()
            dependencies = self._parse_pom_xml(content)
            return self._check_dependencies(dependencies, 'maven')
        except Exception as e:
            return [{'error': f'Maven依赖分析失败: {str(e)}'}]

    def _analyze_npm_dependencies(self, package_file):
        """分析NPM依赖"""
        try:
            with open(package_file, 'r') as f:
                data = json.load(f)
            dependencies = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
            return self._check_dependencies(dependencies, 'npm')
        except Exception as e:
            return [{'error': f'NPM依赖分析失败: {str(e)}'}]

    def _analyze_python_dependencies(self, requirements_file):
        """分析Python依赖"""
        try:
            with open(requirements_file, 'r') as f:
                dependencies = {}
                for line in f:
                    if '==' in line:
                        name, version = line.strip().split('==')
                        dependencies[name] = version
            return self._check_dependencies(dependencies, 'python')
        except Exception as e:
            return [{'error': f'Python依赖分析失败: {str(e)}'}]

    def _check_dependencies(self, dependencies, ecosystem):
        """检查依赖的安全问题"""
        issues = []
        for name, version in dependencies.items():
            # 检查已知漏洞
            vulns = self._check_known_vulnerabilities(name, version, ecosystem)
            if vulns:
                issues.extend(vulns)
            
            # 检查版本过时
            if self._is_outdated_version(name, version, ecosystem):
                issues.append({
                    'type': 'outdated_dependency',
                    'name': name,
                    'current_version': version,
                    'latest_version': self._get_latest_version(name, ecosystem),
                    'ecosystem': ecosystem,
                    'severity': 'medium',
                    'recommendation': '建议更新到最新的稳定版本'
                })
            
            # 检查许可证
            license_issue = self._check_license_compatibility(name, ecosystem)
            if license_issue:
                issues.append(license_issue)
                
        return issues

    def analyze(self, dependencies):
        """分析项目依赖中的安全问题"""
        vulnerabilities = []
        
        for dep in dependencies:
            if dep in self.vulnerability_database:
                vulnerabilities.append({
                    'type': 'vulnerable_dependency',
                    'name': dep,
                    'version': dependencies[dep],
                    'known_vulnerabilities': self.vulnerability_database[dep],
                    'severity': 'high',
                    'recommendation': '更新到最新的安全版本'
                })
                
        return vulnerabilities 