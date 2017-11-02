import datetime
import time
from apscheduler.schedulers.blocking import BlockingScheduler
import MySQLdb

def testing():
    conn = MySQLdb.connect('localhost', 'root', 'root','polls')
    cursor = conn.cursor()
    q = "select * from blog"
    cursor.execute(q)
    data = cursor.fetchall()
    print(data)

scheduler = BlockingScheduler()
scheduler.add_job(testing, 'interval', minutes=1)
scheduler.start()

# To run this go to terminal and run this
# python demotestfile.py>demolog.txt