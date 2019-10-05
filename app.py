from flask import Flask, redirect, render_template, request, session, url_for, jsonify, make_response
from flask_restful import Resource, Api, reqparse
from flask_jwt_extended import JWTManager
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import pbkdf2_sha256 as sha256
import folium
from folium.plugins import FastMarkerCluster
import pandas as pd
from IPython.display import IFrame
import plotly.graph_objects as go
import plotly
import json 

app = Flask(__name__)
# Load data
df_full = pd.read_csv('FinalOut.csv',dtype={'Mirai': str})
df_full.dropna(how='any', inplace = True, subset = ["Latitude","Longitude"])
print(df_full.shape)
df = pd.DataFrame(df_full)
df.dropna(how='any', inplace = True)
df = df.sample(n = 20000)
df_index = df_full.set_index('ip')
mapbox_access_token = open(".mapbox_token").read()
titleurl = "https://api.mapbox.com/styles/v1/matthiasrathbun/cjzkl54et19gf1cpgi3ettgzq.html?fresh=true&title=true"

def makeGraph():
    """
        latitude = df.Latitude.values
        longitude  = df.Longitude.values

    """
    folium_map = folium.Map(location=[df.Latitude.values.mean(), 
                                    df.Longitude.values.mean()],
                                    tiles='cartodbpositron',
                                    zoom_start=4,
                                    width = "100",
                                    height = "100")

    callback = ('function (row) {' 
                'var marker = L.marker(new L.LatLng(row[0], row[1]), {color: "red"});'
                'var icon = L.AwesomeMarkers.icon({'
                "icon: 'info-sign',"
                "iconColor: 'white',"
                "markerColor: 'green',"
                "prefix: 'glyphicon',"
                "extraClasses: 'fa-rotate-0'"
                    '});'
                'marker.setIcon(icon);'
                "var popup = L.popup({maxWidth: '300'});"
                "const display_text = {Country: row[2], City: row[3], IP: row[4], bandwidth: row[5], Label: row[6], confidence: row[7], mirai: row[8], organization: row[9], orgType: row[10]};"
                "var mytext = $(`<div id='mytext' class='display_text' style='width: 100.0%; height: 100.0%;'> <b>IP:</b> ${display_text.IP} <br><b>Location:</b> ${display_text.City}, ${display_text.Country}<br><b>Bandwidth:</b> ${display_text.bandwidth} b/s<br><b>Label:</b> ${display_text.Label}<br><b>Confidence:</b> ${display_text.confidence} <br><b>Mirai:</b> ${display_text.mirai} <br><b>Organization:</b> ${display_text.organization} <br><b>Organization Type:</b> ${display_text.orgType}  </div>`)[0];"
                "popup.setContent(mytext);"
                "marker.bindPopup(popup);"
                'return marker};')

    folium_map.add_child(FastMarkerCluster(df[['Latitude', 'Longitude','Country','City','ip', 'scanning Bandwidth',"Label","Confidence", "Mirai", "Organization", "Organization Type"]].values.tolist(), callback=callback))
    folium_div = folium_map._repr_html_()
    return folium_div
def makeCountryPie():
    df_country = df_full.groupby('Country')['ip'].nunique()
    labels = df_country.sort_values(ascending=False).index.values
    country_values = df_country.sort_values(ascending=False).values
    fig = go.Figure()
    fig.add_trace(go.Pie(labels=labels[:10], 
        values=country_values[:10], domain = dict(x=[0.5,1])
        ,text = "Exploited Devices: " + df_country.sort_values(ascending=False).apply(str).values[:10]))
    fig.add_trace(go.Table(header = dict(values=['Country',"Exploited Devices"]), cells=dict(values = [labels[:10],country_values[:10]])
    ,domain=dict(x=[0, 0.5])))
    fig.update_traces(hoverinfo='label+percent', textinfo='text', textfont_size=9,
                             marker=dict(line=dict(color='#000000', width=0)),selector=dict(type="pie"))
    fig.update_layout(title_text="Top 10 Countries: Exploited Devices")
    fig_json = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    return fig_json
def makeMiraiPie():
    df_mirai = pd.crosstab(df_full["Country"],df_full["Mirai"])
    labels = df_mirai['True'].sort_values(ascending=False).index.values
    mirai_values = df_mirai['True'].sort_values(ascending=False).values
    fig = go.Figure()
    fig.add_trace(go.Pie(labels=labels[:10], 
        values=mirai_values[:10], domain = dict(x=[0.5,1])
        ,text = "Mirai Devices: " + df_mirai['True'].sort_values(ascending=False).apply(str).values[:10]))
    fig.add_trace(go.Table(header = dict(values=['Country',"Mirai Devices"]), cells=dict(values = [labels[:10],mirai_values[:10]])
    ,domain=dict(x=[0, 0.5])))
    fig.update_traces(hoverinfo='label+percent', textinfo='text', textfont_size=9,
                             marker=dict(line=dict(color='#000000', width=0)),selector=dict(type="pie"))
    fig.update_layout(title_text="Top 10 Countries: Mirai Infected Devices")
    fig_json = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    return fig_json
def makeIoTPie():
    df_label = pd.crosstab(df_full["Country"],df_full["Label"])
    labels = df_label['IoT'].sort_values(ascending=False).index.values
    IoT_values = df_label['IoT'].sort_values(ascending=False).values
    fig = go.Figure()
    fig.add_trace(go.Pie(labels=labels[:10], 
        values=IoT_values[:10], domain = dict(x=[0.5,1])
        ,text = "Exploited IoT Devices: " + df_label['IoT'].sort_values(ascending=False).apply(str).values[:10]))
    fig.add_trace(go.Table(header = dict(values=['Country',"Exploited IoT Devices"]), cells=dict(values = [labels[:10],IoT_values[:10]])
    ,domain=dict(x=[0, 0.5])))
    fig.update_traces(hoverinfo='label+percent', textinfo='text', textfont_size=9,
                        marker=dict(line=dict(color='#000000', width=0)),selector=dict(type="pie"))
    fig.update_layout(title_text="Top 10 Countries: Exploited IoT Devices")
    fig_json = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    return fig_json
def makeISPie():
    df_label = df_full.groupby('ISP')['ip'].nunique()
    labels = df_label.sort_values(ascending=False).index.values
    ISP_values = df_label.sort_values(ascending=False).values
    fig = go.Figure()
    fig.add_trace(go.Pie(labels=labels[:20], 
        values=ISP_values[:20], domain = dict(x=[0.5,1])
        ,text = "Exploited Devices: " + df_label.sort_values(ascending=False).apply(str).values[:20]))
    fig.add_trace(go.Table(header = dict(values=['ISP',"Exploited Devices"]), cells=dict(values = [labels[:20],ISP_values[:20]])
    ,domain=dict(x=[0, 0.5])))
    fig.update_traces(hoverinfo='label+percent', textinfo='text', textfont_size=9,
            marker=dict(line=dict(color='#000000', width=0)),selector=dict(type="pie"))
    fig.update_layout(title_text="Top 20 ISP's: Exploited Devices")
    fig_json = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    return fig_json
def makeMiraiISPie():
    df_label = pd.crosstab(df_full["ISP"],df_full["Mirai"])
    labels = df_label["True"].sort_values(ascending=False).index.values
    mirai_values = df_label["True"].sort_values(ascending=False).values
    fig = go.Figure()
    fig.add_trace(go.Pie(labels=labels[:20], 
        values=mirai_values[:20], domain = dict(x=[0.5,1])
        ,text = "Mirai Devices: " + df_label["True"].sort_values(ascending=False).apply(str).values[:20]))
    fig.add_trace(go.Table(header = dict(values=['ISP',"Mirai Devices"]), cells=dict(values = [labels[:20],mirai_values[:20]])
    ,domain=dict(x=[0, 0.5])))
    fig.update_traces(hoverinfo='label+percent', textinfo='text', textfont_size=9,
                             marker=dict(line=dict(color='#000000', width=0)),selector=dict(type="pie"))
    fig.update_layout(title_text="Top 20 ISP's: Mirai Infected Devices")
    fig_json = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    return fig_json
def makeIoTISPie():
    df_label = pd.crosstab(df_full["ISP"],df_full["Label"])
    labels = df_label['IoT'].sort_values(ascending=False).index.values
    IoT_values = df_label['IoT'].sort_values(ascending=False).values
    fig = go.Figure()
    fig.add_trace(go.Pie(labels=labels[:20], 
        values=IoT_values[:20], domain = dict(x=[0.5,1])
        ,text = "Exploited IoT Devices: " + df_label['IoT'].sort_values(ascending=False).apply(str).values[:20]))
    fig.add_trace(go.Table(header = dict(values=['ISP',"Exploited IoT Devices"]), cells=dict(values = [labels[:20],IoT_values[:20]])
    ,domain=dict(x=[0, 0.5])))

    fig.update_traces(hoverinfo='label+percent', textinfo='text', textfont_size=9,
                        marker=dict(line=dict(color='#000000', width=0)),selector=dict(type="pie"))
    fig.update_layout(title_text="Top 20 ISP's: Exploited IoT Devices")
    fig_json = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    return fig_json
def makeSectorPie():
    df_sector = df_full.groupby('Organization Type')['ip'].nunique()
    labels = df_sector.sort_values(ascending=False).index.values
    sector_values = df_sector.sort_values(ascending=False).values
    fig = go.Figure()
    fig.add_trace(go.Pie(labels=labels[:10], 
        values=sector_values[:10], domain = dict(x=[0.5,1])
        ,text = "Devices: " + df_sector.sort_values(ascending=False).apply(str).values[:10]))
    fig.add_trace(go.Table(header = dict(values=['Business Sector',"Exploited Devices"]), cells=dict(values = [labels[:10],sector_values[:10]])
    ,domain=dict(x=[0, 0.5])))
    fig.update_traces(hoverinfo='label+percent', textinfo='text', textfont_size=9,
                             marker=dict(line=dict(color='#000000', width=0)),selector=dict(type="pie"))
    fig.update_layout(title_text="Top 10 Business Sectors: Exploited Devices")
    fig_json = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    return fig_json  
def makeMiraiSectorPie():
    df_mirai = pd.crosstab(df_full["Organization Type"],df_full["Mirai"])
    labels = df_mirai['True'].sort_values(ascending=False).index.values
    mirai_values = df_mirai['True'].sort_values(ascending=False).values
    fig = go.Figure()
    fig.add_trace(go.Pie(labels=labels[:10], 
        values=mirai_values[:10], domain = dict(x=[0.5,1])
        ,text = "Mirai Devices: " + df_mirai['True'].sort_values(ascending=False).apply(str).values[:10]))
    fig.add_trace(go.Table(header = dict(values=['Business Sector',"Mirai Devices"]), cells=dict(values = [labels[:10],mirai_values[:10]])
    ,domain=dict(x=[0, 0.5])))
    fig.update_traces(hoverinfo='label+percent', textinfo='text', textfont_size=9,
                             marker=dict(line=dict(color='#000000', width=0)),selector=dict(type="pie"))
    fig.update_layout(title_text="Top 10 Business Sectors: Mirai Infected Devices")
    fig_json = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    return fig_json
def makeIoTSectorPie():
    df_label = pd.crosstab(df_full["Organization Type"],df_full["Label"])
    labels = df_label['IoT'].sort_values(ascending=False).index.values
    IoT_values = df_label['IoT'].sort_values(ascending=False).values
    fig = go.Figure()
    fig.add_trace(go.Pie(labels=labels[:10], 
        values=IoT_values[:10], domain = dict(x=[0.5,1])
        ,text = "Exploited IoT Devices: " + df_label['IoT'].sort_values(ascending=False).apply(str).values[:10]))
    fig.add_trace(go.Table(header = dict(values=['Business Sector',"Exploited IoT Devices"]), cells=dict(values = [labels[:10],IoT_values[:10]])
    ,domain=dict(x=[0, 0.5])))
    fig.update_traces(hoverinfo='label+percent', textinfo='text', textfont_size=9,
                        marker=dict(line=dict(color='#000000', width=0)),selector=dict(type="pie"))
    fig.update_layout(title_text="Top 10 Business Sectors: Exploited IoT Devices")
    fig_json = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    return fig_json
@app.route('/')
def index():
    folium_div = makeGraph()
    return render_template('index_folium.html', folium_div = folium_div)

@app.route('/country')
def countryReport():
    countryPlot = makeCountryPie()
    miraiPlot = makeMiraiPie()
    IoTPlot = makeIoTPie()
    return render_template('reports.html', Plot = countryPlot, 
    IoTPlot = IoTPlot, MiraiPlot = miraiPlot)

@app.route('/isp')
def ispReport():
    ISP_Plot = makeISPie()
    mirai_ISP = makeMiraiISPie()
    IoT_ISP = makeIoTISPie()
    return render_template('reports.html', Plot = ISP_Plot, IoTPlot = IoT_ISP, MiraiPlot = mirai_ISP)

@app.route('/sector')
def sectorReport():
    Sector_Plot = makeSectorPie()
    mirai_sector = makeMiraiSectorPie()
    IoT_sector = makeIoTSectorPie()
    return render_template('reports.html', Plot = Sector_Plot, IoTPlot = IoT_sector, MiraiPlot = mirai_sector)

if __name__ == '__main__':
    app.run(debug=True)