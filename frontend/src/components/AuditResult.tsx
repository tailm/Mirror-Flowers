import React from 'react';

interface AIAnalysis {
  vulnerability_confirmation: {
    dangerous_function: {
      is_false_positive: boolean;
      evidence: string;
    };
  };
  impact_analysis: {
    dangerous_function: {
      severity: string;
      exploit_conditions: string;
      impact_scope: string;
    };
  };
  remediation_suggestions: {
    dangerous_function: {
      code_level_fix: string;
      secure_coding_practices: string;
      security_configuration_suggestions: string;
    };
  };
  correlation_analysis: {
    dangerous_function: {
      association: string;
      exploit_combination: string;
      overall_remediation_strategy: string;
    };
  };
}

interface AuditResultProps {
  result: {
    status: string;
    message: string;
    project_type: string;
    suspicious_files: Array<{
      file_path: string;
      issues: Array<{
        type: string;
        line: number;
        description: string;
        severity: string;
      }>;
    }>;
    ai_verification: {
      [key: string]: {
        issues: Array<any>;
        similar_code: Array<any>;
        ai_analysis: {
          status: string;
          analysis: {
            raw_text: string;
            summary: {
              risk_level: string;
              vulnerability_count: number;
            };
          };
        };
      };
    };
    summary: {
      total_files: number;
      suspicious_files: number;
      total_issues: number;
      risk_level: string;
    };
  };
}

const AuditResult: React.FC<AuditResultProps> = ({ result }) => {
  const renderAIAnalysis = (aiVerification: AuditResultProps['result']['ai_verification']) => {
    if (!aiVerification) {
      console.log('No AI verification data');
      return null;
    }

    const fileAnalysis = Object.values(aiVerification)[0];
    if (!fileAnalysis?.ai_analysis?.analysis?.raw_text) {
      console.log('No raw text in analysis');
      return null;
    }

    try {
      const analysis: AIAnalysis = JSON.parse(fileAnalysis.ai_analysis.analysis.raw_text);

      return (
        <div className="ai-analysis">
          <h3>AI 分析建议:</h3>
          
          {/* 漏洞确认 */}
          <div className="section">
            <h4>漏洞确认</h4>
            <p>{analysis.vulnerability_confirmation.dangerous_function.evidence}</p>
            <p>是否误报: {analysis.vulnerability_confirmation.dangerous_function.is_false_positive ? '是' : '否'}</p>
          </div>

          {/* 影响分析 */}
          <div className="section">
            <h4>影响分析</h4>
            <ul>
              <li><strong>严重程度:</strong> {analysis.impact_analysis.dangerous_function.severity}</li>
              <li><strong>利用条件:</strong> {analysis.impact_analysis.dangerous_function.exploit_conditions}</li>
              <li><strong>影响范围:</strong> {analysis.impact_analysis.dangerous_function.impact_scope}</li>
            </ul>
          </div>

          {/* 修复建议 */}
          <div className="section">
            <h4>修复建议</h4>
            <ul>
              <li><strong>代码级修复:</strong> {analysis.remediation_suggestions.dangerous_function.code_level_fix}</li>
              <li><strong>安全编码实践:</strong> {analysis.remediation_suggestions.dangerous_function.secure_coding_practices}</li>
              <li><strong>安全配置建议:</strong> {analysis.remediation_suggestions.dangerous_function.security_configuration_suggestions}</li>
            </ul>
          </div>

          {/* 关联分析 */}
          <div className="section">
            <h4>关联分析</h4>
            <ul>
              <li><strong>关联性:</strong> {analysis.correlation_analysis.dangerous_function.association}</li>
              <li><strong>组合利用:</strong> {analysis.correlation_analysis.dangerous_function.exploit_combination}</li>
              <li><strong>整体修复策略:</strong> {analysis.correlation_analysis.dangerous_function.overall_remediation_strategy}</li>
            </ul>
          </div>
        </div>
      );
    } catch (e) {
      console.error('解析 AI 分析结果失败:', e);
      return (
        <div className="ai-analysis error">
          <h3>AI 分析建议解析失败</h3>
          <p>错误信息: {(e as Error).message}</p>
          <pre>{fileAnalysis.ai_analysis.analysis.raw_text}</pre>
        </div>
      );
    }
  };

  return (
    <div className="audit-result">
      {/* 审计摘要 */}
      <div className="audit-summary">
        <h2>审计摘要</h2>
        <ul>
          <li>状态: {result.status}</li>
          <li>消息: {result.message}</li>
          <li>发现可疑文件数: {result.summary.suspicious_files}</li>
          <li>总问题数: {result.summary.total_issues}</li>
          <li>风险等级: {result.summary.risk_level.toUpperCase()}</li>
        </ul>
      </div>

      {/* 可疑文件列表 */}
      {result.suspicious_files.map((file, index) => (
        <div key={index} className="suspicious-file">
          <h3>{file.file_path.split('\\').pop()}</h3>
          <div className="issues">
            {file.issues.map((issue, i) => (
              <div key={i} className="issue">
                <span className={`severity ${issue.severity}`}>{issue.severity.toUpperCase()}</span>
                <p>{issue.description}</p>
                <p>行号: {issue.line}</p>
              </div>
            ))}
          </div>
          {renderAIAnalysis(result.ai_verification)}
        </div>
      ))}
    </div>
  );
};

export default AuditResult; 