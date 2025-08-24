#!/usr/bin/env python3
"""
BLACKFANG INTELLIGENCE - MINIMAL WORKING VERSION
This WILL work on Railway without crashes
"""

import os
from datetime import datetime
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
import uvicorn

# Initialize FastAPI
app = FastAPI(title="BlackFang Intelligence", version="2.0.0")

# Add CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

@app.get("/")
async def root():
    return {
        "message": "🎯 BlackFang Intelligence API",
        "status": "operational",
        "version": "2.0.0",
        "demo_url": "/app"
    }

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/api/auth/login")
async def login(request: Request):
    try:
        data = await request.json()
        email = data.get('email', '')
        password = data.get('password', '')
        
        if email == 'demo@blackfangintel.com' and password == 'demo123':
            return {
                "success": True,
                "user": {
                    "id": 1,
                    "name": "Demo Automotive Dealership",
                    "email": email,
                    "company_name": "Demo Motors Pvt Ltd"
                }
            }
        else:
            raise HTTPException(status_code=401, detail="Invalid credentials")
    except Exception as e:
        raise HTTPException(status_code=400, detail="Login failed")

@app.get("/app", response_class=HTMLResponse)
async def serve_app():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>BlackFang Intelligence</title>
        <style>
            body {
                font-family: system-ui, -apple-system, sans-serif;
                background: linear-gradient(135deg, #0c0c0c, #1a1a1a);
                color: white;
                margin: 0;
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .container {
                background: linear-gradient(135deg, #1e1e1e, #2a2a2a);
                padding: 50px;
                border-radius: 20px;
                box-shadow: 0 25px 50px rgba(0,0,0,0.5);
                max-width: 400px;
                width: 100%;
                border-top: 4px solid #dc2626;
            }
            h1 {
                text-align: center;
                font-size: 28px;
                background: linear-gradient(135deg, #dc2626, #f59e0b);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                margin-bottom: 10px;
            }
            p {
                text-align: center;
                color: #888;
                margin-bottom: 30px;
            }
            .form-group {
                margin-bottom: 20px;
            }
            label {
                display: block;
                margin-bottom: 8px;
                color: #ccc;
                font-weight: 500;
            }
            input {
                width: 100%;
                padding: 15px;
                border: 2px solid #333;
                background: rgba(0,0,0,0.3);
                color: white;
                border-radius: 10px;
                font-size: 16px;
                transition: border-color 0.3s;
            }
            input:focus {
                outline: none;
                border-color: #dc2626;
            }
            .btn {
                width: 100%;
                padding: 15px;
                background: linear-gradient(135deg, #dc2626, #b91c1c);
                border: none;
                border-radius: 10px;
                color: white;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                transition: transform 0.2s;
            }
            .btn:hover {
                transform: translateY(-2px);
            }
            .demo-info {
                margin-top: 30px;
                padding: 20px;
                background: rgba(220, 38, 38, 0.1);
                border-radius: 10px;
                border-left: 4px solid #dc2626;
            }
            .demo-info h3 {
                color: #dc2626;
                margin-bottom: 10px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>⚡ BLACKFANG INTELLIGENCE</h1>
            <p>Professional Competitive Intelligence</p>
            
            <form id="loginForm">
                <div class="form-group">
                    <label>Email</label>
                    <input type="email" id="email" value="demo@blackfangintel.com" required>
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" id="password" value="demo123" required>
                </div>
                <button type="submit" class="btn">Access Intelligence Platform</button>
            </form>
            
            <div class="demo-info">
                <h3>Demo Account</h3>
                <p><strong>Email:</strong> demo@blackfangintel.com</p>
                <p><strong>Password:</strong> demo123</p>
                <p>Experience professional competitive intelligence with real-time monitoring.</p>
            </div>
        </div>
        
        <script>
            document.getElementById('loginForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                
                const email = document.getElementById('email').value;
                const password = document.getElementById('password').value;
                
                try {
                    const response = await fetch('/api/auth/login', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ email, password })
                    });
                    
                    const data = await response.json();
                    
                    if (data.success) {
                        window.location.href = `/dashboard/${data.user.id}`;
                    } else {
                        alert('Login failed: ' + (data.detail || 'Invalid credentials'));
                    }
                } catch (error) {
                    alert('Error: ' + error.message);
                }
            });
        </script>
    </body>
    </html>
    """

@app.get("/dashboard/{company_id}", response_class=HTMLResponse)
async def serve_dashboard(company_id: int):
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>BlackFang Intelligence - Dashboard</title>
        <style>
            body {{
                font-family: system-ui, -apple-system, sans-serif;
                background: linear-gradient(135deg, #0c0c0c, #1a1a1a);
                color: white;
                margin: 0;
            }}
            .header {{
                background: linear-gradient(135deg, #1e1e1e, #2a2a2a);
                padding: 20px 0;
                border-bottom: 1px solid rgba(220,38,38,0.3);
            }}
            .header-content {{
                max-width: 1200px;
                margin: 0 auto;
                padding: 0 20px;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }}
            .brand {{
                font-size: 24px;
                font-weight: 700;
                background: linear-gradient(135deg, #dc2626, #f59e0b);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            }}
            .container {{
                max-width: 1200px;
                margin: 0 auto;
                padding: 30px 20px;
            }}
            .stats-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }}
            .stat-card {{
                background: linear-gradient(135deg, #1e1e1e, #2a2a2a);
                padding: 30px;
                border-radius: 15px;
                border-left: 5px solid #dc2626;
                box-shadow: 0 10px 25px rgba(0,0,0,0.3);
            }}
            .stat-number {{
                font-size: 40px;
                font-weight: 800;
                background: linear-gradient(135deg, #dc2626, #f59e0b);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                margin-bottom: 8px;
            }}
            .stat-label {{
                color: #ccc;
                font-size: 16px;
            }}
            .section {{
                background: linear-gradient(135deg, #1e1e1e, #2a2a2a);
                padding: 30px;
                border-radius: 15px;
                margin-bottom: 25px;
                box-shadow: 0 10px 25px rgba(0,0,0,0.3);
            }}
            .section-title {{
                font-size: 22px;
                font-weight: 700;
                color: #dc2626;
                margin-bottom: 20px;
            }}
            .alert {{
                background: #333;
                padding: 20px;
                margin: 15px 0;
                border-radius: 10px;
                border-left: 5px solid #dc2626;
            }}
            .alert-title {{
                font-size: 18px;
                font-weight: 700;
                margin-bottom: 10px;
            }}
            .competitor {{
                background: #333;
                padding: 20px;
                margin: 15px 0;
                border-radius: 10px;
                border-left: 5px solid #666;
            }}
            .competitor h4 {{
                margin-bottom: 10px;
                color: #fff;
            }}
            .btn {{
                background: linear-gradient(135deg, #dc2626, #b91c1c);
                color: white;
                padding: 10px 20px;
                border: none;
                border-radius: 8px;
                cursor: pointer;
                margin-bottom: 20px;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <div class="header-content">
                <div class="brand">⚡ BLACKFANG INTELLIGENCE</div>
                <div style="color: #888;">Live Intelligence Dashboard</div>
            </div>
        </div>
        
        <div class="container">
            <button class="btn" onclick="refresh()">🔄 Refresh Data</button>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">3</div>
                    <div class="stat-label">Competitors Monitored</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">8</div>
                    <div class="stat-label">Active Alerts</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">2</div>
                    <div class="stat-label">High Priority Threats</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">24/7</div>
                    <div class="stat-label">Real-time Monitoring</div>
                </div>
            </div>
            
            <div class="section">
                <div class="section-title">🚨 Critical Threat Intelligence</div>
                
                <div class="alert">
                    <div class="alert-title">🔴 HIGH PRIORITY: Price War Detected - AutoMax Dealers</div>
                    <p>Competitor dropped Honda City prices by 8% (₹95,000 reduction). Immediate market impact expected.</p>
                    <p><strong>Strategic Response:</strong> Consider immediate price matching or launch "Superior Service Value" campaign.</p>
                    <small>⏰ Detected: 2 hours ago | Confidence: 95%</small>
                </div>
                
                <div class="alert">
                    <div class="alert-title">🟡 MEDIUM ALERT: Aggressive Promotion - Speed Motors</div>
                    <p>New campaign "Monsoon Special - Extra 5% off + Free Insurance" launched across all channels.</p>
                    <p><strong>Strategic Response:</strong> Deploy counter-promotional strategy within 48 hours.</p>
                    <small>⏰ Detected: 5 hours ago | Confidence: 88%</small>
                </div>
                
                <div class="alert">
                    <div class="alert-title">🟡 OPPORTUNITY: Service Issues - Elite Auto</div>
                    <p>3 negative reviews about delivery delays posted in past 24 hours. Customer sentiment declining.</p>
                    <p><strong>Strategic Response:</strong> Target "Fast & Reliable Service" in marketing campaigns.</p>
                    <small>⏰ Detected: 8 hours ago | Confidence: 92%</small>
                </div>
            </div>
            
            <div class="section">
                <div class="section-title">👥 Competitor Intelligence Network</div>
                
                <div class="competitor">
                    <h4>🎯 AutoMax Dealers</h4>
                    <p><strong>Website:</strong> cars24.com | <strong>Threat Level:</strong> <span style="color:#dc2626;">HIGH ACTIVITY</span></p>
                    <p><strong>Intelligence:</strong> Aggressive pricing strategy. 8% price reduction on premium models targeting market expansion.</p>
                </div>
                
                <div class="competitor">
                    <h4>⚡ Speed Motors</h4>
                    <p><strong>Website:</strong> carwale.com | <strong>Threat Level:</strong> <span style="color:#f59e0b;">MEDIUM ACTIVITY</span></p>
                    <p><strong>Intelligence:</strong> Promotional focus with seasonal campaigns and strong digital marketing presence.</p>
                </div>
                
                <div class="competitor">
                    <h4>🚗 Elite Auto</h4>
                    <p><strong>Website:</strong> cardekho.com | <strong>Threat Level:</strong> <span style="color:#10b981;">LOW ACTIVITY</span></p>
                    <p><strong>Intelligence:</strong> Service quality issues. Customer complaints about delivery delays present opportunity.</p>
                </div>
            </div>
        </div>
        
        <script>
            function refresh() {{
                alert('Intelligence data refreshed successfully!');
            }}
        </script>
    </body>
    </html>
    """

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8080))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
