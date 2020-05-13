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

##################################################
##               ROOM METHODS                  ###
##################################################


    def getRooms(self):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        cursor.execute("SELECT ID FROM Espaco")
        result = [l[0] for l in cursor.fetchall()]
        db_con.close()
        return result

    def getRoom(self, roomid):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        cursor.execute("SELECT Nome,Descricao FROM Espaco WHERE ID = %s", (str(roomid),))
        result = cursor.fetchone()
        result = {"name" : result[0], "description" : result[1]}
        db_con.close()
        return result

    def createRoom(self, roomid, roomdata, sensors):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        cursor.execute("INSERT INTO Espaco VALUES (%s, %s, %s);", (str(roomid), roomdata["name"], roomdata["description"]))
        for s in sensors:
            cursor.execute("UPDATE Sensor SET ID_Espaco = %s WHERE ID = %s;", (str(roomid), s))
        db_con.commit()
        db_con.close()


    def updateRoom(self,roomid, new_details):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()

        if "name" in new_details:
            cursor.execute("UPDATE Espaco SET Nome = %s WHERE ID = %s;", (new_details["name"], roomid))
        if "description" in new_details:
            cursor.execute("UPDATE Espaco SET Descricao = %s WHERE ID = %s;", (new_details["description"], roomid))
        db_con.commit()
        db_con.close()


    def deleteRoom(self, roomid):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        cursor.execute("DELETE FROM Espaco WHERE Espaco.ID = %s;", (str(roomid),))
        db_con.commit()
        db_con.close()





    def getSensorsFromRoom(self, roomid):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        cursor.execute("SELECT Sensor.ID FROM Espaco JOIN Sensor ON Espaco.ID=Sensor.ID_Espaco WHERE Espaco.ID = %s", (str(roomid),))
        result = [l[0] for l in cursor.fetchall()]
        db_con.close()
        return result


    def getSensorsFullDescriptionFromRoom(self, roomid):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        cursor.execute("SELECT Sensor.ID, Sensor.Descricao, Nome_TipoSensor, Simbolo FROM Espaco JOIN Sensor ON Espaco.ID=Sensor.ID_Espaco WHERE Espaco.ID = %s", (str(roomid),))
        tuplos = cursor.fetchall()
        result = []

        for t in tuplos:
            result.append({"id" : t[0], "description": t[1], "data" : {"type" : t[2], "unit_symbol" : t[3]}})

        db_con.close()
        return result

    def updateSensorsFromRoom(self, roomid, changes):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        for s in changes["add"]:
            cursor.execute("UPDATE Sensor SET ID_Espaco = %s WHERE ID = %s;", (str(roomid), s))

        for s in changes["remove"]:
            cursor.execute("UPDATE Sensor SET ID_Espaco = Null WHERE ID = %s;", (str(roomid),))

        db_con.commit()
        db_con.close()






    def roomExists(self, roomid):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        cursor.execute("SELECT Nome FROM Espaco WHERE ID = %s;", (roomid,))
        if cursor.fetchone() == None:
            db_con.close()
            return False
        db_con.close()
        return True






##################################################
##               SENSORS METHODS               ###
##################################################


    def getAllSensors(self):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        cursor.execute("SELECT id FROM Sensor;")
        res = cursor.fetchall()
        db_con.close()
        return res


    def getSensor(self, sensorid):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        cursor.execute("SELECT Sensor.Descricao,Nome_TipoSensor,Simbolo,Espaco.ID FROM Sensor JOIN Espaco ON Sensor.ID_Espaco=Espaco.ID WHERE Sensor.ID = %s",  (sensorid,))
        result = cursor.fetchone()
        result = {"description" : result[0],
                "data" : { "type": result[1], "unit_symbol": result[2]},
                "room_id": result[3]
                }
        db_con.close()
        return result





    def createSensor(self, sensorid, sensordata):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()

        if "description" not in sensordata:
            sensordata["description"] = "Null"
        if "room_id" not in sensordata:
            sensordata["room_id"] = "Null"

        cursor.execute("INSERT INTO Sensor VALUES (%s, %s, %s, %s, '%s');", (str(sensorid), sensordata["description"], sensordata["data"]["type"], sensordata["data"]["unit_symbol"], sensordata["room_id"]))
        db_con.commit()
        db_con.close()


    def updateSensor(self, sensorid, sensordata):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        if "description" in sensordata:
            cursor.execute("UPDATE Sensor SET Descricao = %s WHERE ID = %s;", (sensordata["description"], str(sensorid)))
        if "data" in sensordata and "type" in sensordata["data"]:
            cursor.execute("UPDATE Sensor SET Nome_TipoSensor = %s WHERE ID = %s;", (sensordata["data"]["type"], str(sensorid)))
        if "data" in sensordata and "unit_symbol" in sensordata["data"]:
            cursor.execute("UPDATE Sensor SET Simbolo = %s WHERE ID = %s;", (sensordata["data"]["unit_symbol"], str(sensorid)))
        if "room_id" in sensordata:
            cursor.execute("UPDATE Sensor SET ID_Espaco = %s WHERE ID = %s;", (sensordata["room_id"], str(sensorid)))

        db_con.commit()
        db_con.close()

    def deleteSensor(self, sensorid):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        cursor.execute("DELETE FROM Sensor WHERE Sensor.ID = %s;", (str(sensorid),))
        db_con.commit()
        db_con.close()




    def isSensorFree(self, sensorid):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        cursor.execute("SELECT ID_Espaco FROM Sensor WHERE id=%s;", (str(sensorid),))
        result = cursor.fetchone()

        if result == None :
            raise ValueError
        if result == "Null":
            return True
        return False

    def isSensorRoom(self, sensorid, roomid):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        cursor.execute("SELECT ID_Espaco FROM Sensor WHERE id=%s;", (str(sensorid),))
        result = cursor.fetchone()

        if result == None :
            raise ValueError
        if result == roomid:
            return True
        return False










    ##################################################
    ##            SENSORS TYPES METHODS            ###
    ##################################################


    def getAllSensorTypes(self):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        cursor.execute("SELECT id FROM TipoSensor;")
        res = cursor.fetchall()
        db_con.close()
        return res

    def getSensorType(self, id):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        ##TODO verificar se esta query funciona como esperado
        cursor.execute(
            "SELECT Descricao, Simbolo FROM (SELECT Nome FROM TipoSensor WHERE id = %s) as X JOIN Sensor ON X.Nome = Nome_TipoSensor;",
            (str(id),))

        l_tuplos = cursor.fetchall()
        if not l_tuplos:
            l_tuplos = cursor.execute("SELECT * FROM TipoSensor WHERE id = %s;", (str(id),))
        
        l_simbolos = [t[1] for t in l_tuplos]
        description = l_tuplos[0][0]

        db_con.close()
        return {"description": description, "units": l_simbolos}



    def createSensorType(self, details):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        id = cursor.execute("INSERT INTO TipoSensor (Nome, Descricao) VALUES (%s, %s) RETURNING id;", (details["name"], details["description"]))
        db_con.commit()
        db_con.close()
        return id



    def updateSensorType(self, id, new_details):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        if "name" in new_details:
            cursor.execute("UPDATE TipoSensor SET Nome = %s WHERE id = %s;", (new_details["name"], str(id)))

        if "description" in new_details:
            cursor.execute("UPDATE TipoSensor SET Descricao = %s WHERE id = %s;", (new_details["description"], str(id)))

        db_con.commit()
        db_con.close()

    def deleteSensorType(self, id):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        cursor.execute("DELETE FROM TipoSensor WHERE id = %s;", (str(id),))
        db_con.commit()
        db_con.close()




    def datatypeNameExists(self, name):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        cursor.execute("SELECT Descricao FROM TipoSensor WHERE Nome = %s;", (str(name),))
        if cursor.fetchone() == None:
            db_con.close()
            return False
        db_con.close()
        return True

    def datatypeIdExists(self, id):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        cursor.execute("SELECT Descricao FROM TipoSensor WHERE id = %s;", (str(id),))
        if cursor.fetchone() == None:
            db_con.close()
            return False
        db_con.close()
        return True



    # TODO pode rebentar
    def getSensorsFromType(self, id):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        cursor.execture("")
        cursor.execute(
            "SELECT Sensor.id FROM (SELECT Nome FROM TipoSensor WHERE id = %s) as X JOIN Sensor ON Nome_TipoSensor = X.Nome;",
            (str(id),))
        l_tuplos = cursor.fetchall()
        db_con.close()

        if l_tuplos == None:
            return []
        return [t[0] for t in l_tuplos]





    ##################################################
    ##                  USER METHODS              ###
    ##################################################


    def getUsers(self):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        cursor.execute("SELECT uuid FROM Utilizador;")
        l_tuplos = cursor.fetchall()
        db_con.close()
        return [t[0] for t in l_tuplos]


    def getUsersFull(self):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        cursor.execute("SELECT uuid, Email, admin FROM Utilizador;")
        l_tuplos = cursor.fetchall()
        db_con.close()
        return [{"id": t[0] ,"email" : t[1],"admin": t[2]} for t in l_tuplos]


    def getUser(self, userid):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        cursor.execute("SELECT email, admin FROM Utilizador WHERE uuid = %s;", (str(userid),))
        tuplo = cursor.fetchone()
        db_con.close()
        return {"email": tuplo[0], "admin": tuplo[1]}


    #TODO pode rebentar
    def InsertUser(self, userid, userdata):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        id = cursor.execute("INSERT INTO Utilizador VALUES (%s, %s, %s); RETURNING id", (str(userid), userdata["email"], userdata["admin"]))
        db_con.commit()
        db_con.close()
        return id

    def hasUser(self, userid):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        cursor.execute("SELECT * FROM Utilizador WHERE uuid = %s;", (str(id),))
        if cursor.fetchone() == None:
            db_con.close()
            return False
        db_con.close()
        return True

    def changeUserAdmin(self, userid, admin_state):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        cursor.execute("UPDATE Utilizador SET admin = %s WHERE uuid = %s;", (str(admin_state), str(userid)))
        db_con.commit()
        db_con.close()

    def deleteUser(self, userid):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        cursor.execute("DELETE FROM Utilizador WHERE uuid = %s;", (str(userid),))
        db_con.commit()
        db_con.close()
        

    def isAdmin(self, userid):
        db_con = psycopg2.connect(host=self.url, port=self.port, user=self.user, password=self._pw, dbname=self.db)
        cursor = db_con.cursor()
        cursor.execute("SELECT admin FROM Utilizador WHERE uuid = %s;", (userid,))
        res = cursor.fetchone()
        if not res:
            return False
        db_con.close()
        return bool(res[0])