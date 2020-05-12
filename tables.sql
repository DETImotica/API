CREATE DATABASE detimoticadb;

\c detimoticadb

CREATE TABLE Espaco (
	ID UUID not null,
	Nome varchar(50),  			--Piso Numero, null caso nao seja numa sala Ex. Secretaria
	Descricao varchar(50),		--Descrição da sala quaso Nome == null
	PRIMARY KEY (ID),
	Unique (Nome) 				--maybe
);

CREATE TABLE TipoSensor (
	id SERIAL,
	Nome varchar(50) not null,			--EX Temperatura
	Descricao varchar(50),		--Não sei bem que dados seriam aqui
	PRIMARY KEY (Nome)
);

CREATE TABLE Sensor (
	id UUID not null,
	Descricao varchar(50),		--Marca, intervalo de medicao, erro de medicao
	Nome_TipoSensor varchar(50) not null,
	Simbolo varchar(3) not null,			--EX ºC
	ID_Espaco UUID,
	PRIMARY KEY (ID),
	FOREIGN KEY (ID_Espaco) REFERENCES Espaco(ID) ON DELETE SET NULL,
	FOREIGN KEY (Nome_TipoSensor) REFERENCES TipoSensor(Nome) ON UPDATE CASCADE
);


CREATE TABLE Utilizador (
	uuid UUID,
	Email varchar(50) not null,
	admin BOOLEAN default false,
	           -- grupo a que pertence (vai depender
								  -- de como fazemos as politicas)
	PRIMARY KEY(uuid)
	UNIQUE(Email),
	
);







