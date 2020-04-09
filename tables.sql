CREATE DATABASE detimoticadb;

CREATE TABLE Espaco (
	ID varchar(50) not null,
	Nome varchar(50),  			--Piso Numero, null caso nao seja numa sala Ex. Secretaria
	Descricao varchar(50),		--Descrição da sala quaso Nome == null
	PRIMARY KEY (ID),
	Unique (Nome) 				--maybe
);


CREATE TABLE TipoSensor (
	Nome varchar(50) not null,			--EX Temperatura
	Descricao varchar(50),		--Não sei bem que dados seriam aqui
	PRIMARY KEY (Nome),
);

CREATE TABLE Sensor (
	ID varchar(50) not null,
	Descricao varchar(50),		--Marca, intervalo de medicao, erro de medicao
	Nome_TipoSensor varchar(50) not null,
	Simbolo varchar(3) not null,			--EX ºC
	ID_Espaco varchar(50) not null,
	PRIMARY KEY (ID),
	FOREIGN KEY (ID_Espaco) REFERENCES Espaco(ID),
	FOREIGN KEY (Nome_TipoSensor) REFERENCES TipoSensor(Nome)
);


CREATE TABLE Utilizador (
	Email varchar(50) not null,
	Perfil varchar(50)            -- grupo a que pertence (vai depender
								  -- de como fazemos as politicas)
	PRIMARY KEY (Email)
);







