import psycopg2

def getRooms():
    db_con = psycopg2.connect(host=hostname, user=username, password=password, dbname=database)
    cursor = db_con.cursor()
    cursor.execute("SELECT ID FROM Espaco")
    result = cursor.fetchall()
    db_con.close()
    return result




def getRoom(roomid):
    db_con = psycopg2.connect(host=hostname, user=username, password=password, dbname=database)
    cursor = db_con.cursor()
    cursor.execute("SELECT Nome,Descricao FROM Espaco WHERE ID = %s", (roomid))
    result = cursor.fetchone()
    result = {"name" : result[0], "description" : result[1]}
    db_con.close()
    return result

def createRoom(roomid, roomdata, sensors):
    db_con = psycopg2.connect(host=hostname, user=username, password=password, dbname=database)
    cursor = db_con.cursor()
    cursor.execute("INSERT INTO Espaco VALUES (%s, %s, %s);", (roomid, roomdata["name"], roomdata["description"]))
    for s in sensors:
        cursor.execute("UPDATE Sensor SET ID_Espaco = %s WHERE ID = %s;", (roomid, s))
    db_con.close()



def getSensorsFromRoom(roomid):
    db_con = psycopg2.connect(host=hostname, user=username, password=password, dbname=database)
    cursor = db_con.cursor()
    cursor.execute("SELECT Sensor.ID FROM Espaco JOIN Sensor ON Espaco.ID=Sensor.ID_Espaco WHERE Espaco.ID = %s", (roomid))
    result = cursor.fetchall()
    db_con.close()
    return result

def updateSensorsFromRoom(roomid, changes):
    db_con = psycopg2.connect(host=hostname, user=username, password=password, dbname=database)
    cursor = db_con.cursor()
    for s in changes["add"]:
        cursor.execute("UPDATE Sensor SET ID_Espaco = %s WHERE ID = %s;", (roomid, s))

    for s in changes["remove"]:
        cursor.execute("UPDATE Sensor SET ID_Espaco = Null WHERE ID = %s;", (roomid, s))

    db_con.close()






def getSensor(sensorid):
    db_con = psycopg2.connect(host=hostname, user=username, password=password, dbname=database)
    cursor = db_con.cursor()
    cursor.execute("SELECT Sensor.Descricao,Nome_TipoSensor,Simbolo,Nome,Espaco.Descricao FROM Sensor JOIN Espaco ON Sensor.ID_Espaco=Espaco.ID WHERE Sensor.ID = %s",  (sensorid))
    result = cursor.fetchone()
    result = {"description" : result[0],
              "data" : { "type": result[1], "unit_symbol": result[2]},
              "room" : { "name": result[3], "description": result[4]}
              }
    db_con.close()
    return result

def createSensor(sensorid, sensordata):
    db_con = psycopg2.connect(host=hostname, user=username, password=password, dbname=database)
    cursor = db_con.cursor()
    cursor.execute("INSERT INTO Sensor VALUES (%s, %s, %s, %s, NULL);",(sensorid, sensordata["description"], sensordata["data"]["type"], sensordata["data"]["unit_symbol"]))
    db_con.close()


def updateSensor(sensorid, sensordata):
    db_con = psycopg2.connect(host=hostname, user=username, password=password, dbname=database)
    cursor = db_con.cursor()
    cursor.execute("UPDATE Sensor SET ID_Espaco = %s WHERE ID = %s;", (sensordata["room_id"], sensorid))
    db_con.close()
