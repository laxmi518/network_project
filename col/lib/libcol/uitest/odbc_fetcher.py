
import pyodbc

DRIVER = "FreeTDS"

def test(server, port, database, username, password, query = 'select *'):
	conn = pyodbc.connect('DRIVER=%s;SERVER=%s;PORT=%s;DATABASE=%s;UID=%s;PWD=%s;TDS_Version=8.0;' % (DRIVER, server, port, database, username, password))
	cursor = conn.cursor()
	for row in cursor.execute('%s;' % query):
	    print row.Result

if __name__ == '__main__':
	test('127.0.0.1', 2021,'test', 'user', 'password', 'select * from user')