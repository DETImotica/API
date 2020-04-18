import configparser
import psycopg2

class PGDB(object):
    '''Relational database class definition.'''

    def __init__(self):
        config = configparser.ConfigParser()
        config.read('options.conf')

        self.url = config['postgresql']['URL']
        self.port = config['postgresql']['PORT']
        self.db = config['postgresql']['DB']
        self.user = config['postgresql']['USER']
        self._pw = config['postgresql']['PW']

    def __str__(self):
        return f"PGDB -> (url={self.url},port={self.port},user={self.user},db={self.db})"

    def __repr__(self):
        return self.__str__()

    def getRooms(self):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        cursor.execute("SELECT ID FROM Espaco")
        result = cursor.fetchall()
        db_con.close()
        return result

    def getRoom(self, roomid):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        cursor.execute("SELECT Nome,Descricao FROM Espaco WHERE ID = %s", (roomid))
        result = cursor.fetchone()
        result = {"name" : result[0], "description" : result[1]}
        db_con.close()
        return result

    def updateRoom(self,roomid, new_details):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()

        if "name" in new_details:
            cursor.execute("UPDATE Espaco SET Nome = %s WHERE ID = %s;", (new_details["name"], roomid))
        if "description" in new_details:
            cursor.execute("UPDATE Espaco SET Descricao = %s WHERE ID = %s;", (new_details["description"], roomid))

        db_con.close()


    def createRoom(self, roomid, roomdata, sensors):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        cursor.execute("INSERT INTO Espaco VALUES (%s, %s, %s);", (roomid, roomdata["name"], roomdata["description"]))
        for s in sensors:
            cursor.execute("UPDATE Sensor SET ID_Espaco = %s WHERE ID = %s;", (roomid, s))
        db_con.close()



    def getSensorsFromRoom(self, roomid):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        cursor.execute("SELECT Sensor.ID FROM Espaco JOIN Sensor ON Espaco.ID=Sensor.ID_Espaco WHERE Espaco.ID = %s", (roomid))
        result = cursor.fetchall()
        db_con.close()
        return result

    def updateSensorsFromRoom(self, roomid, changes):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        for s in changes["add"]:
            cursor.execute("UPDATE Sensor SET ID_Espaco = %s WHERE ID = %s;", (roomid, s))

        for s in changes["remove"]:
            cursor.execute("UPDATE Sensor SET ID_Espaco = Null WHERE ID = %s;", (roomid, s))

        db_con.close()

    def getSensor(self, sensorid):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        cursor.execute("SELECT Sensor.Descricao,Nome_TipoSensor,Simbolo,Nome,Espaco.Descricao FROM Sensor JOIN Espaco ON Sensor.ID_Espaco=Espaco.ID WHERE Sensor.ID = %s",  (sensorid))
        result = cursor.fetchone()
        result = {"description" : result[0],
                "data" : { "type": result[1], "unit_symbol": result[2]},
                "room" : { "name": result[3], "description": result[4]}
                }
        db_con.close()
        return result

    def createSensor(self, sensorid, sensordata):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        cursor.execute("INSERT INTO Sensor VALUES (%s, %s, %s, %s, NULL);",(sensorid, sensordata["description"], sensordata["data"]["type"], sensordata["data"]["unit_symbol"]))
        db_con.close()


    def updateSensor(self, sensorid, sensordata):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        if "description" in sensordata:
            cursor.execute("UPDATE Sensor SET Descricao = %s WHERE ID = %s;", (sensordata["description"], sensorid))
        if "data" in sensordata and "type" in sensordata["data"]:
            cursor.execute("UPDATE Sensor SET Nome_TipoSensor = %s WHERE ID = %s;", (sensordata["data"]["type"], sensorid))
        if "data" in sensordata and "unit_symbol" in sensordata["data"]:
            cursor.execute("UPDATE Sensor SET Simbolo = %s WHERE ID = %s;", (sensordata["data"]["unit_symbol"], sensorid))
        db_con.close()

    def isSensorFree(self, sensorid):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        cursor.execute("SELECT ID_Espaco FROM Sensor WHERE id='%s';", (sensorid,))
        result = cursor.fetchone()

        if result == None :
            raise ValueError
        if result == "Null":
            return True
        return False

    def isSensorRoom(self, sensorid, roomid):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        cursor.execute("SELECT ID_Espaco FROM Sensor WHERE id='%s';", (sensorid,))
        result = cursor.fetchone()

        if result == None :
            raise ValueError
        if result == roomid:
            return True
        return False

    def roomExists(self, roomid):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        cursor.execute("SELECT Nome FROM Espaco WHERE ID = %s;", (roomid,))
        if cursor.fetchone() == None:
            db_con.close()
            return False
        db_con.close()
        return True

    def isAdmin(self, userid):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        cursor.execute("SELECT admin FROM Utilizador WHERE uuid = '%s';", (userid,))
        res = cursor.fetchone()
        db_con.close()
        return bool(res[0])
