<template>
  <div class="container">
    <h1>AI代码审计工具</h1>
    
    <!-- API配置部分 -->
    <div class="config-section">
      <h2>API配置</h2>
      <div class="form-group">
        <input 
          type="text" 
          v-model="apiKey" 
          placeholder="OpenAI API Key"
        >
        <input 
          type="text" 
          v-model="apiBase" 
          placeholder="API Base URL（可选）"
        >
        <button @click="updateConfig">更新配置</button>
      </div>
    </div>
    
    <div class="upload-section">
      <input type="file" @change="handleFileUpload" accept=".php,.java">
      <button @click="startAudit" :disabled="!selectedFile">开始审计</button>
    </div>
    
    <div class="results-section" v-if="auditResults">
      <h2>审计结果</h2>
      
      <div class="analysis-card">
        <h3>第一轮分析</h3>
        <pre>{{ auditResults.first_analysis }}</pre>
      </div>
      
      <div class="analysis-card">
        <h3>第二轮验证</h3>
        <pre>{{ auditResults.second_analysis }}</pre>
      </div>
    </div>
    
    <div class="loading" v-if="loading">
      分析中...
    </div>
  </div>
</template>

<script>
export default {
  data() {
    return {
      selectedFile: null,
      auditResults: null,
      loading: false,
      apiKey: '',
      apiBase: ''
    }
  },
  methods: {
    async updateConfig() {
      try {
        const response = await fetch('http://localhost:8000/api/configure', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            api_key: this.apiKey,
            api_base: this.apiBase || undefined
          })
        });
        
        if (response.ok) {
          alert('API配置已更新');
        } else {
          throw new Error('配置更新失败');
        }
      } catch (error) {
        console.error('配置更新失败:', error);
        alert('配置更新失败');
      }
    },
    
    handleFileUpload(event) {
      this.selectedFile = event.target.files[0]
    },
    
    async startAudit() {
      if (!this.selectedFile) return
      
      this.loading = true
      const formData = new FormData()
      formData.append('file', this.selectedFile)
      
      // 添加API配置
      if (this.apiKey) {
        formData.append('api_key', this.apiKey)
      }
      if (this.apiBase) {
        formData.append('api_base', this.apiBase)
      }
      
      try {
        const response = await fetch('http://localhost:8000/api/audit', {
          method: 'POST',
          body: formData
        })
        
        if (!response.ok) {
          throw new Error('审计请求失败')
        }
        
        this.auditResults = await response.json()
      } catch (error) {
        console.error('审计失败:', error)
        alert('审计过程中发生错误')
      } finally {
        this.loading = false
      }
    }
  }
}
</script>

<style scoped>
.container {
  max-width: 1200px;
  margin: 0 auto;
  padding: 20px;
}

.config-section {
  margin: 20px 0;
  padding: 20px;
  background: #f8f9fa;
  border-radius: 8px;
}

.form-group {
  display: flex;
  gap: 10px;
  margin: 10px 0;
}

input[type="text"] {
  flex: 1;
  padding: 8px;
  border: 1px solid #ddd;
  border-radius: 4px;
}

.upload-section {
  margin: 20px 0;
}

.analysis-card {
  background: #f5f5f5;
  padding: 20px;
  margin: 10px 0;
  border-radius: 8px;
}

.loading {
  text-align: center;
  margin: 20px 0;
  font-size: 18px;
}
</style> 