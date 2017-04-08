import xml.etree.ElementTree as ET
import os
import bs4

def main():
    path = os.path.abspath(os.path.curdir) + "\\app01\\payloads\\xss.html"
    fp = open(path, 'r')
    soup = bs4.BeautifulSoup(fp)
    result = soup.find_all('pre')
    result = [i.text for i in result]
