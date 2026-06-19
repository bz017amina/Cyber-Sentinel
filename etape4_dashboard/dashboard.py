import dash
from dash import dcc, html, dash_table
from dash.dependencies import Input, Output
from confluent_kafka import Consumer
import json
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from threading import Thread
from datetime import datetime

# --- CONFIGURATION KAFKA ---
conf = {
    'bootstrap.servers': '127.0.0.1:9092',
    'group.id': 'ids_cyber_sentinel_fullwidth_v2',
    'auto.offset.reset': 'earliest'
}
consumer = Consumer(conf)
consumer.subscribe(['alertes_ids'])

alertes_memoire = []

def ecouter_kafka():
    while True:
        msg = consumer.poll(0.5)
        if msg is not None and not msg.error():
            try:
                alerte = json.loads(msg.value().decode('utf-8'))
                alerte['time_key'] = datetime.now().strftime("%H:%M:%S")
                alertes_memoire.append(alerte)
                if len(alertes_memoire) > 100: alertes_memoire.pop(0)
            except: pass

Thread(target=ecouter_kafka, daemon=True).start()

# --- INITIALISATION DASH ---
app = dash.Dash(__name__, external_stylesheets=['https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css'])

app.layout = html.Div(className='app-shell', children=[
    
    # 1. HEADER
    html.Div(className='header-row', children=[
        html.Div(className='brand', children=[
            html.Div(className='brand-icon', children=[html.I(className="fas fa-shield-halved")]),
            html.Div([
                html.H1("IDS CYBER-SENTINEL", className='brand-title'),
                html.P("Real-time GPU Accelerated Intrusion Detection", className='brand-subtitle')
            ])
        ]),
        html.Div(className='header-status', children=[
            html.Div(className='live-indicator', children=[
                html.Div(className='live-dot'),
                html.Span("System Live", className='live-label')
            ]),
            html.H4(id="live-clock", className='live-clock')
        ])
    ]),

    # 2. KPI ROW (4 colonnes égales)
    html.Div(className='kpi-row', children=[
        html.Div(className='kpi-col', children=[
            html.Div(className='kpi-card', children=[
                html.Div(className='kpi-icon', children=[html.I(className="fas fa-bolt")], style={'color': '#e5484d', 'backgroundColor': 'rgba(229, 72, 77, 0.1)'}),
                html.Div([html.P("Total Alerts", className='kpi-label'), html.H2(id="kpi-total", className='kpi-value')])
            ])
        ]),
        html.Div(className='kpi-col', children=[
            html.Div(className='kpi-card', children=[
                html.Div(className='kpi-icon', children=[html.I(className="fas fa-skull")], style={'color': '#f0a23a', 'backgroundColor': 'rgba(240, 162, 58, 0.1)'}),
                html.Div([html.P("Primary Threat", className='kpi-label'), html.H2(id="kpi-dominant", className='kpi-value')])
            ])
        ]),
        html.Div(className='kpi-col', children=[
            html.Div(className='kpi-card', children=[
                html.Div(className='kpi-icon', children=[html.I(className="fas fa-network-wired")], style={'color': '#4c8bf5', 'backgroundColor': 'rgba(76, 139, 245, 0.1)'}),
                html.Div([html.P("Last Source IP", className='kpi-label'), html.H2(id="kpi-ip", className='kpi-value')])
            ])
        ]),
        html.Div(className='kpi-col', children=[
            html.Div(className='kpi-card', children=[
                html.Div(className='kpi-icon', children=[html.I(className="fas fa-microchip")], style={'color': '#3dd68c', 'backgroundColor': 'rgba(61, 214, 140, 0.1)'}),
                html.Div([html.P("Engine Mode", className='kpi-label'), html.H2("GPU CUDA", className='kpi-value', style={'color': '#3dd68c'})])
            ])
        ]),
    ]),

    # 3. MAIN ROW
    html.Div(className='main-row', children=[
        # Table Panel (7/12)
        html.Div(className='col-table', children=[
            html.Div(className='panel', children=[
                html.Div("Intrusion Event Logs", className='panel-header'),
                html.Div(className='panel-body', children=[
                    dash_table.DataTable(
                        id='table-alertes',
                        columns=[
                            {"name": "Time", "id": "timestamp"},
                            {"name": "Type", "id": "type"},
                            {"name": "Source IP", "id": "ip_source"},
                            {"name": "Details", "id": "ports"}
                        ],
                        style_header={'backgroundColor': 'transparent', 'color': '#8b94a3', 'fontWeight': '700', 'borderBottom': '1px solid #1f242d'},
                        style_cell={'backgroundColor': 'transparent', 'color': '#e7e9ec', 'border': 'none', 'textAlign': 'left', 'padding': '12px', 'fontFamily': 'JetBrains Mono'},
                        style_data_conditional=[
                            {'if': {'filter_query': '{type} contains "DDoS"'}, 'color': '#e5484d', 'fontWeight': 'bold'},
                            {'if': {'filter_query': '{type} contains "Scan"'}, 'color': '#f0a23a'},
                        ],
                        page_size=12
                    )
                ])
            ])
        ]),
        
        # Charts Panel (5/12)
        html.Div(className='col-charts', children=[
            html.Div(className='panel', children=[
                html.Div("Threat Distribution", className='panel-header'),
                html.Div(className='panel-body', children=[
                    dcc.Graph(id='graph-pie', config={'displayModeBar': False}, style={'height': '300px'})
                ]),
                html.Div("Traffic Intensity", className='panel-subheader', style={'paddingLeft':'20px'}),
                html.Div(className='panel-body', children=[
                    dcc.Graph(id='graph-line', config={'displayModeBar': False}, style={'height': '180px'})
                ])
            ])
        ])
    ]),

    dcc.Interval(id='interval-update', interval=1000, n_intervals=0)
])

# --- CALLBACKS ---
@app.callback(
    [Output('table-alertes', 'data'), Output('graph-pie', 'figure'), Output('graph-line', 'figure'),
     Output('kpi-total', 'children'), Output('kpi-dominant', 'children'), Output('kpi-ip', 'children'), Output('live-clock', 'children')],
    [Input('interval-update', 'n_intervals')]
)
def refresh(n):
    now = datetime.now().strftime("%H:%M:%S")
    if not alertes_memoire:
        return [], go.Figure(), go.Figure(), "0", "N/A", "N/A", now

    df = pd.DataFrame(alertes_memoire)
    
    # Pie Chart
    fig_pie = px.pie(df, names='type', hole=0.7, color_discrete_map={'DDoS': '#e5484d', 'Port Scan': '#f0a23a', 'Flood': '#4c8bf5'})
    fig_pie.update_layout(template="plotly_dark", margin=dict(l=20, r=20, b=20, t=20), paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', showlegend=True)

    # Line Chart
    df_line = df.groupby('time_key').size().reset_index(name='count')
    fig_line = px.line(df_line, x='time_key', y='count')
    fig_line.update_traces(line_color='#4c8bf5', fill='tozeroy', line_width=3)
    fig_line.update_layout(template="plotly_dark", margin=dict(l=0, r=0, b=0, t=0), paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', xaxis_visible=False, yaxis_visible=False)

    return df.iloc[::-1].to_dict('records'), fig_pie, fig_line, str(len(df)), df['type'].mode()[0], df['ip_source'].iloc[-1], now

if __name__ == '__main__':
    app.run(debug=False, port=8050)