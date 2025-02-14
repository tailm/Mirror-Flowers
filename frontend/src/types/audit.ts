export interface AIAnalysisResult {
  vulnerability_confirmation?: {
    dangerous_function?: {
      is_false_positive?: boolean;
      evidence?: string;
    };
  };
  impact_analysis?: {
    dangerous_function?: {
      severity?: string;
      exploit_conditions?: string;
      impact_scope?: string;
    };
  };
  remediation_suggestions?: {
    dangerous_function?: {
      code_level_fix?: string;
      secure_coding_practices?: string;
      security_configuration_suggestions?: string;
    };
  };
  correlation_analysis?: {
    dangerous_function?: {
      association?: string;
      exploit_combination?: string;
      overall_remediation_strategy?: string;
    };
  };
} 