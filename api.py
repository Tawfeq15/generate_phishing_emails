#!/usr/bin/env python3
# coding: utf-8
"""
api.py — Phishing Training API - FIXED
✅ 100+ Names | ✅ 30+ Offers | ✅ VT Built-in
⚠️ FOR CYBERSECURITY TRAINING ONLY ⚠️
"""

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import List, Optional

from generate_phishing_emails import generate_bulk_for_companies_fast as generate_bulk_for_companies
from generate_phishing_emails import sanitize_filename

app = FastAPI(title="🔴 Phishing Training API")

class BulkGenerateRequest(BaseModel):
    company_names: List[str]
    offer: Optional[str] = None
    n_per_company: int = 20
    max_workers: int = 16
    save_files: bool = True
    check_virustotal: bool = False  # Disabled by default due to rate limits
    output_format: str = "both"  # Options: "both", "csv", "txt"

class CompanyResult(BaseModel):
    name: str
    emails_generated: int
    txt_file: str
    csv_file: str

class BulkGenerateResponse(BaseModel):
    ok: bool
    companies: List[CompanyResult]
    warning: str = "⚠️ FOR TRAINING ONLY"

@app.post("/generate_bulk", response_model=BulkGenerateResponse)
def generate_bulk_endpoint(request: BulkGenerateRequest):
    try:
        if not request.company_names:
            raise HTTPException(status_code=400, detail="company_names cannot be empty")
        
        all_messages = generate_bulk_for_companies(
            company_names=request.company_names,
            n_per_company=request.n_per_company,
            offer=request.offer,
            display_name_template="{company} team",
            max_workers=request.max_workers,
            save_files=request.save_files,
            check_virustotal=request.check_virustotal,
            output_format=request.output_format
        )
        
        companies_result = []
        for company in request.company_names:
            company_messages = [m for m in all_messages if m.get('company_name') == company]
            safe_name = sanitize_filename(company)
            companies_result.append(
                CompanyResult(
                    name=company,
                    emails_generated=len(company_messages),
                    txt_file=f"Generated Emails/generated_phishing_emails_{safe_name}.txt",
                    csv_file=f"Generated Emails/generated_phishing_emails_{safe_name}.csv",
                )
            )
        
        return BulkGenerateResponse(ok=True, companies=companies_result)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/", response_class=HTMLResponse)
def home():
    return """
<!DOCTYPE html>
<html dir="rtl" lang="ar">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔴 INSANE DIVERSITY: 138K Names, 12K Subjects, 7M Bodies - ALL DOUBLED!</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 900px;
            margin: 30px auto;
            padding: 30px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .warning-box {
            background: #fff3cd;
            border: 3px solid #ffc107;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            text-align: center;
        }
        .warning-box h2 {
            color: #856404;
            margin: 0 0 10px 0;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
        }
        h1 { color: #667eea; text-align: center; margin-bottom: 10px; }
        .subtitle { text-align: center; color: #555; margin-bottom: 30px; font-size: 14px; }
        .badge { background: #667eea; color: white; padding: 4px 12px; border-radius: 20px; font-size: 12px; margin: 0 5px; }
        .feature-list { background: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
        .feature-list ul { margin: 10px 0; padding-right: 20px; }
        .feature-list li { margin: 5px 0; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; color: #34495e; font-weight: 600; }
        input, textarea, select { width: 100%; padding: 12px; border: 2px solid #e0e0e0; border-radius: 8px; box-sizing: border-box; font-family: inherit; }
        textarea { min-height: 120px; font-family: 'Courier New', monospace; }
        .checkbox-group { display: flex; align-items: center; gap: 10px; }
        .checkbox-group input[type="checkbox"] { width: auto; }
        button { width: 100%; padding: 15px; background: linear-gradient(135deg, #667eea, #764ba2); color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: bold; cursor: pointer; transition: all 0.3s; }
        button:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4); }
        button:disabled { background: #95a5a6; cursor: not-allowed; transform: none; }
        #status-box { margin-top: 30px; padding: 20px; border-radius: 8px; display: none; }
        #status-box.success { background: #d4edda; border: 2px solid #c3e6cb; color: #155724; }
        #status-box.error { background: #f8d7da; border: 2px solid #f5c6cb; color: #721c24; }
        #status-box.loading { background: #d1ecf1; border: 2px solid #bee5eb; color: #0c5460; }
        .company-result { background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 6px; border-right: 4px solid #667eea; }
        .help-text { font-size: 13px; color: #7f8c8d; margin-top: 5px; }
        .spinner { display: inline-block; width: 20px; height: 20px; border: 3px solid rgba(255,255,255,.3); border-radius: 50%; border-top-color: #fff; animation: spin 1s ease-in-out infinite; }
        @keyframes spin { to { transform: rotate(360deg); } }
        .stats { display: flex; gap: 20px; justify-content: space-around; margin: 20px 0; }
        .stat-box { flex: 1; background: linear-gradient(135deg, #667eea, #764ba2); color: white; padding: 20px; border-radius: 8px; text-align: center; }
        .stat-number { font-size: 32px; font-weight: bold; margin-bottom: 5px; }
        .stat-label { font-size: 14px; opacity: 0.9; }
    </style>
</head>
<body>
    <div class="warning-box">
        <h2>⚠️ تحذير - للتدريب الأمني فقط ⚠️</h2>
        <p><strong>هذه الأداة للتدريب على الأمن السيبراني فقط</strong></p>
        <p>🔴 URLs حقيقية malicious - ليست Google/Dropbox/Microsoft</p>
        <p>استخدامها لأغراض ضارة غير قانوني ويعاقب عليه القانون</p>
    </div>

    <div class="container">
        <h1>🔴 INSANE DIVERSITY - ALL DOUBLED!</h1>
        <p class="subtitle">
            <span class="badge">✅ 690+ Names</span>
            <span class="badge">✅ 12K+ Subjects</span>
            <span class="badge">✅ 7M+ Bodies</span>
            <span class="badge">✅ QUADRILLIONS</span>
        </p>
        
        <div class="stats">
            <div class="stat-box">
                <div class="stat-number">138K</div>
                <div class="stat-label">Name Combos</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">12K+</div>
                <div class="stat-label">Subjects</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">7M+</div>
                <div class="stat-label">Body Variations</div>
            </div>
        </div>
        
        <div class="feature-list">
            <strong>🔥 INSANE DIVERSITY - ALL DOUBLED:</strong>
            <ul>
                <li>✅ <strong>690 first names</strong> (DOUBLED: عربي + English + Spanish + French + German + Italian + Russian)</li>
                <li>✅ <strong>200 last names</strong> = 138,000 name combinations (DOUBLED)</li>
                <li>✅ <strong>100 email domains</strong> (DOUBLED: Gmail, Yahoo, Outlook, Privacy, Business, Regional, Asian)</li>
                <li>✅ <strong>428 subjects × 30 prefixes</strong> = 12,840 subject variations (DOUBLED)</li>
                <li>✅ <strong>16 body templates</strong> with dynamic content (DOUBLED)</li>
                <li>✅ <strong>20 greetings</strong> (DOUBLED)</li>
                <li>✅ <strong>30 closings</strong> (DOUBLED)</li>
                <li>✅ <strong>40 action phrases</strong> (DOUBLED)</li>
                <li>✅ <strong>24 time urgencies</strong> (DOUBLED)</li>
                <li>✅ <strong>20 company email patterns</strong> (DOUBLED)</li>
                <li>✅ <strong>14 sender name variants</strong> (DOUBLED)</li>
                <li>🔴 <strong>REAL malicious URLs - NO Google/Dropbox/Microsoft</strong></li>
                <li>✅ <strong>7,372,800 body combinations</strong> (16 × 20 × 30 × 40 × 24)</li>
                <li>✅ <strong>QUADRILLIONS of total combinations!</strong></li>
                <li>✅ تكرار مستحيل تماماً لأي dataset</li>
                <li>✅ استغلال 64GB RAM (16 workers)</li>
                <li>✅ سرعة عالية: 2-3 دقائق لـ 20 إيميل</li>
                <li>⚠️ VirusTotal اختياري (بطيء - rate limits)</li>
            </ul>
        </div>
        
        <form id="generateForm" onsubmit="return false;">
            <div class="form-group">
                <label>أسماء الشركات (شركة بكل سطر) *</label>
                <textarea id="company_names" placeholder="Adobe&#10;Microsoft&#10;Amazon&#10;Netflix" required></textarea>
                <div class="help-text">💡 يمكنك إدخال عدة شركات</div>
            </div>

            <div class="form-group">
                <label>نوع العرض 🎯</label>
                <select id="offer_type">
                    <option value="random">عروض عشوائية مشبوهة (12K+ نوع - موصى به)</option>
                    <option value="custom">عرض مخصص</option>
                </select>
                <input type="text" id="custom_offer" style="display:none; margin-top:10px;" placeholder="مثال: Urgent: Verify your account">
                <div class="help-text">
                    💡 12,840 subject variations (428 base × 30 prefixes) - ALL DOUBLED!<br>
                    13 فئة متنوعة: Account, Payment, Prizes, Delivery, Security, Password, Documents, Subscriptions, Tax, Bank, Service Updates, Social Media, Email<br>
                    30 prefixes: URGENT, IMPORTANT, ACTION REQUIRED, SECURITY ALERT, etc.<br>
                    🔴 URLs ستكون REAL malicious (NO Google/Dropbox)
                </div>
            </div>

            <div class="form-group">
                <label>عدد الرسائل لكل شركة 📧</label>
                <input type="number" id="n_per_company" value="20" min="1" max="200">
                <div class="help-text">
                    💡 بدون VT: 20 إيميل = ~2 دقيقة ⚡<br>
                    ⚠️ مع VT: 20 إيميل = ~13 دقيقة 🐌
                </div>
            </div>

            <div class="form-group">
                <label>نوع الملفات الناتجة 📁</label>
                <select id="output_format">
                    <option value="both">TXT + CSV (كلاهما - موصى به) ✅</option>
                    <option value="csv">CSV فقط (للـ ML)</option>
                    <option value="txt">TXT فقط (قراءة سهلة)</option>
                </select>
                <div class="help-text">
                    💡 اختر نوع الملفات:<br>
                    • <strong>Both</strong>: TXT (human-readable) + CSV (ML-ready)<br>
                    • <strong>CSV only</strong>: مناسب للـ machine learning<br>
                    • <strong>TXT only</strong>: مناسب للقراءة السريعة
                </div>
            </div>

            <div class="form-group">
                <label>عدد الـ Workers ⚡</label>
                <input type="number" id="max_workers" value="16" min="1" max="32">
                <div class="help-text">💡 16 workers = استغلال كامل لـ 64GB RAM</div>
            </div>

            <div class="form-group checkbox-group">
                <input type="checkbox" id="check_virustotal">
                <label for="check_virustotal" style="margin:0;">فحص URLs مع VirusTotal (اختياري - بطيء جداً)</label>
            </div>
            <div class="help-text" style="margin-top: -10px; margin-right: 30px;">
                ⚠️ <strong>تحذير:</strong> VT يستغرق ~35 ثانية لكل URL<br>
                ⚠️ Free API: 4 requests/minute فقط (rate limits قوية)<br>
                💡 <strong>موصى به:</strong> اترك معطل للسرعة (2-3 دقائق بدون VT)
            </div>

            <button type="button" onclick="submitForm()" id="submitBtn">
                <span id="btnText">🔴 توليد إيميلات REAL malicious (NO Google/Dropbox)</span>
            </button>
        </form>

        <div id="status-box"></div>
    </div>

    <script>
        // Show/hide custom offer input
        document.getElementById('offer_type').addEventListener('change', function(e) {
            const customOffer = document.getElementById('custom_offer');
            customOffer.style.display = e.target.value === 'custom' ? 'block' : 'none';
        });

        // Form submission
        async function submitForm() {
            const submitBtn = document.getElementById('submitBtn');
            const btnText = document.getElementById('btnText');
            const statusBox = document.getElementById('status-box');
            
            // Disable button
            submitBtn.disabled = true;
            btnText.innerHTML = '<span class="spinner"></span> جاري التوليد...';
            
            // Show loading status
            statusBox.className = 'loading';
            statusBox.style.display = 'block';
            
            const checkVT = document.getElementById('check_virustotal').checked;
            const nEmails = parseInt(document.getElementById('n_per_company').value) || 20;
            const estimatedTime = checkVT ? Math.round(nEmails * 40 / 60) : Math.round(nEmails * 0.1);
            
            if (checkVT) {
                statusBox.innerHTML = `<strong>⏳ جاري التوليد مع فحص VirusTotal...</strong><br>
                ⚠️ <strong>بطيء جداً:</strong> ~${estimatedTime} دقيقة (40s لكل URL)<br>
                💡 قد تحدث أخطاء rate limit (429)`;
            } else {
                statusBox.innerHTML = `<strong>⏳ جاري إنشاء REAL malicious URLs...</strong><br>
                🔴 NO Google/Dropbox/Microsoft<br>
                الوقت المتوقع: ~${estimatedTime} دقيقة`;
            }

            try {
                // Get company names
                const companyNames = document.getElementById('company_names').value
                    .split('\\n')
                    .map(s => s.trim())
                    .filter(s => s.length > 0);
                
                if (companyNames.length === 0) {
                    throw new Error('الرجاء إدخال اسم شركة واحدة على الأقل');
                }

                // Get offer
                const offerType = document.getElementById('offer_type').value;
                const offer = offerType === 'custom' ? 
                    (document.getElementById('custom_offer').value || null) : null;
                
                // Get output format
                const outputFormat = document.getElementById('output_format').value || 'both';

                // Prepare request data
                const requestData = {
                    company_names: companyNames,
                    offer: offer,
                    n_per_company: nEmails,
                    max_workers: parseInt(document.getElementById('max_workers').value) || 16,
                    check_virustotal: checkVT,
                    output_format: outputFormat,
                    save_files: true
                };

                console.log('Sending request:', requestData);

                // Send request
                const response = await fetch('/generate_bulk', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(requestData)
                });

                const data = await response.json();
                
                if (!response.ok) {
                    throw new Error(data.detail || 'خطأ في الخادم');
                }

                // Show success
                statusBox.className = 'success';
                let html = '<strong>✅ تم إنشاء إيميلات بـ REAL malicious URLs!</strong><br><br>';
                
                data.companies.forEach((c, i) => {
                    html += `<div class="company-result">
                        <strong>${i+1}. ${c.name}</strong><br>
                        عدد الإيميلات: ${c.emails_generated}<br>
                        <small>📄 ${c.txt_file}<br>📊 ${c.csv_file}</small>
                    </div>`;
                });
                
                html += '<br><div class="help-text">🔴 REAL malicious URLs - NO Google/Dropbox/Microsoft</div>';
                html += '<div class="help-text">📁 الملفات في: Generated Emails/</div>';
                statusBox.innerHTML = html;

            } catch (error) {
                console.error('Error:', error);
                statusBox.className = 'error';
                statusBox.innerHTML = `<strong>❌ خطأ</strong><br>${error.message}`;
            } finally {
                // Re-enable button
                submitBtn.disabled = false;
                btnText.textContent = '🔴 توليد إيميلات REAL malicious (NO Google/Dropbox)';
            }
        }

        // Allow Enter key in textarea
        document.getElementById('company_names').addEventListener('keydown', function(e) {
            if (e.key === 'Enter' && e.ctrlKey) {
                submitForm();
            }
        });
    </script>
</body>
</html>
    """

if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*70)
    print("🔴 INSANE DIVERSITY - ALL DOUBLED!")
    print("="*70)
    print("✅ 138K Names | ✅ 12K Subjects | ✅ 7M Bodies | ✅ QUADRILLIONS!")
    print("="*70)
    print("🌐 Opening: http://localhost:8000")
    print("="*70 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=8000)