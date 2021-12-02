import streamlit as st
import pandas as pd
import numpy as np
import plotly.figure_factory as ff
import matplotlib.pyplot as pltst.title(‘Food Demand Forecasting — Analytics Vidhya’)
@st.cache
def load_data(nrows):
data = pd.read_csv('train.csv', nrows=nrows)
return data@st.cache
def load_center_data(nrows):
data = pd.read_csv('fulfilment_center_info.csv',nrows=nrows)
return data@st.cache
def load_meal_data(nrows):
data = pd.read_csv('meal_info.csv',nrows=nrows)
return data