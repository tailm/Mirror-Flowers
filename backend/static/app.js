async function uploadProject() {
    const fileInput = document.getElementById('projectFile');
    const file = fileInput.files[0];
    if (!file) {
        alert('请选择项目文件');
        return;
    }

    const formData = new FormData();
    formData.append('project', file);

    try {
        const response = await fetch('/api/audit/project', {
            method: 'POST',
            body: formData
        });

        const result = await response.json();
        displayResults(result);
    } catch (error) {
        console.error('审计失败:', error);
        alert('审计过程中发生错误');
    }
}

function displayResults(result) {
    const resultsDiv = document.getElementById('results');
    // 显示审计结果的逻辑
    // ...
} 