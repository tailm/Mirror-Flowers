export interface AuditResult {
    status: string;
    message?: string;
    suspicious_files: Array<{
        file_path: string;
        issues: Array<{
            type: string;
            description: string;
            severity: string;
            line: number | null;
        }>;
        language: string;
    }>;
    ai_verification: Record<string, {
        issues: Array<any>;
        similar_code: Array<any>;
        ai_analysis: {
            status: string;
            analysis: {
                vulnerabilities: Array<any>;
                recommendations: Array<{
                    issue_type: string;
                    description: string;
                    severity: string;
                    fix: string;
                    best_practices: string;
                }>;
                impact_analysis: Array<{
                    issue_type: string;
                    actual_harm: string;
                    exploit_conditions: string;
                    scope: string;
                }>;
            };
        };
    }>;
    summary: {
        total_files: number;
        total_issues: number;
        risk_level: string;
    };
    recommendations: Array<{
        file: string;
        recommendation: string;
    }>;
}

export interface SuspiciousFile {
    file_path: string;
    issues: {
        taint: TaintIssue[];
        security: SecurityIssue[];
        framework: FrameworkIssue[];
    };
}

export interface AIVerification {
    issues: Record<string, any>;
    similar_code: SimilarCode[];
    ai_analysis: AIAnalysis;
}

export interface AuditReport {
    summary: {
        total_files: number;
        total_issues: number;
        risk_level: string;
    };
    details: {
        suspicious_files: SuspiciousFile[];
        ai_verification: Record<string, AIVerification>;
    };
    recommendations: Recommendation[];
} 