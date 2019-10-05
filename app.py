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

# Add Tokens for Login
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)
app.config['JWT_SECRET_KEY'] = 'jwt-secret-string'
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
#app.config['JWT_REFRESH_COOKIE_PATH'] = '/token/refresh' and '/logout/refresh'
jwt = JWTManager(app)
app.config['JWT_COOKIE_CSRF_PROTECT'] = False
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
api = Api(app)

@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return RevokedTokenModel.is_jti_blacklisted(jti)

# User Database connection
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'some-secret-string'
db = SQLAlchemy(app)

@app.before_first_request
def create_tables():
    db.create_all()

class UserModel(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(120), unique = True, nullable = False)
    password = db.Column(db.String(120), nullable = False)
    
    def save_to_db(self):
        db.session.add(self)
        db.session.commit()
    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username = username).first()
    @classmethod
    def return_all(cls):
        def to_json(x):
            return {
                'username': x.username,
                'password': x.password
            }
        return {'users': list(map(lambda x: to_json(x), UserModel.query.all()))}

    @classmethod
    def delete_all(cls):
        try:
            num_rows_deleted = db.session.query(cls).delete()
            db.session.commit()
            return {'message': '{} row(s) deleted'.format(num_rows_deleted)}
        except:
            return {'message': 'Something went wrong'}
    @staticmethod
    def generate_hash(password):
        return sha256.hash(password)
    @staticmethod
    def verify_hash(password, hash):
        return sha256.verify(password, hash) 
# Define Parsers
userParser = reqparse.RequestParser()
userParser.add_argument('username', help = 'This field cannot be blank', required = True)
userParser.add_argument('password', help = 'This field cannot be blank', required = True)


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

class Dashboard(Resource):
    def get(self):
        folium_div = makeGraph()
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('index_folium.html', folium_div = folium_div),headers)

class Home(Resource):
    def get(self):
        resp = make_response(redirect('http://127.0.0.1:5000/login'))
        return resp

class UserLogoutAccess(Resource):
    @jwt_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti = jti)
            revoked_token.add()
            return {'message': 'Access token has been revoked'}
        except:
            return {'message': 'Something went wrong'}, 500

class UserLogoutRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti = jti)
            revoked_token.add()
            return {'message': 'Refresh token has been revoked'}
        except:
            return {'message': 'Something went wrong'}, 500

class TokenRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        current_user = get_jwt_identity()
        access_token = create_access_token(identity = current_user)
        return {'access_token': access_token}

class AllUsers(Resource):
    def get(self):
        return UserModel.return_all()
    
    def delete(self):
        return UserModel.delete_all()

class SecretResource(Resource):
    @jwt_required
    def get(self):
        return {
            'answer': 42
        }

class RevokedTokenModel(db.Model):
    __tablename__ = 'revoked_tokens'
    id = db.Column(db.Integer, primary_key = True)
    jti = db.Column(db.String(120))
    
    def add(self):
        db.session.add(self)
        db.session.commit()
    
    @classmethod
    def is_jti_blacklisted(cls, jti):
        query = cls.query.filter_by(jti = jti).first()
        return bool(query)

class UserRegistration(Resource):
    def post(self):
        data = userParser.parse_args()

        if UserModel.find_by_username(data['username']):
            resp = make_response(redirect('http://127.0.0.1:5000/login'))
            return resp

        new_user = UserModel(
            username = data['username'],
            password = UserModel.generate_hash(data['password'])
            )
        try:
            resp = make_response(redirect('http://127.0.0.1:5000/login'))
            new_user.save_to_db()
            return resp
        except:
            return {'message': 'Something went wrong'}, 500
    def get(self):
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('registration.html'),headers)
class UserLogin(Resource):
    def post(self):
        data = userParser.parse_args()
        current_user = UserModel.find_by_username(data['username'])
        if not current_user:
            resp = make_response(redirect('http://127.0.0.1:5000/register'))
            return resp

        
        if UserModel.verify_hash(data['password'], current_user.password):
            access_token = create_access_token(identity = data['username'])
            refresh_token = create_refresh_token(identity = data['username'])
            resp = make_response(redirect('http://127.0.0.1:5000/dashboard'))
            resp.set_cookie('access_token_cookie', access_token)
            resp.set_cookie('refresh_token_cookie', refresh_token)
            return resp
        else:
            return {'message': 'Wrong credentials'}
    def get(self):
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('login.html'),headers)

"""
@app.route('/')
def index():
    folium_div = makeGraph()
    return render_template('index_folium.html', folium_div = folium_div)

@app.route('/login', methods = ['GET'])

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
"""

api.add_resource(Dashboard, '/dashboard')
api.add_resource(Home, '/')
api.add_resource(UserRegistration, '/register')
api.add_resource(UserLogin, '/login')
api.add_resource(UserLogoutAccess, '/logout/access')
api.add_resource(UserLogoutRefresh, '/logout/refresh')
api.add_resource(TokenRefresh, '/token/refresh')
api.add_resource(AllUsers, '/users')
api.add_resource(SecretResource, '/secret')
if __name__ == '__main__':
    app.run(debug=True)