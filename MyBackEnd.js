const conf = require('./config.js')
const express = require('express');
const crypto = require('crypto');
const bodyParser = require("body-parser");
const Axios = require('axios'); 
const fs = require('fs');
const path = require('path');
const knex = require('knex')(conf.MySQL)
const key = new require('node-rsa')(conf.RSAPrivateKey);


const app = express();
var ipTables = {};

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({extended: true}))
app.use( (error, req, res, next) => (error instanceof SyntaxError) ? res.send({Mess: "JSON Error"}) : next())

app.use( (req, res, next) =>{
	res.removeHeader("ETag")
	res.removeHeader("X-Powered-By")
	next()
})

app.use( (req, res, next) =>{
	var ip = req.get("x-forwarded-for")// 
	var time = Date.now()
	if (ip in ipTables){
		if (time - ipTables[ip].time > 6000){
			ipTables[ip] = { count : 1, time }            
		} else {
			ipTables[ip].count++;
        	ipTables[ip].time = time;
			if (ipTables[ip].count > 5) {
				res.status(429).send({Mess: "Слишком много запросов!"})
				return
			}			
		}

	} else { ipTables[ip] = {count: 1, time} }	
	next()
})

function Myhash (text) {	
	return crypto.createHash('sha256').update(text).digest('hex');
}

app.post('/api/login', async (request, response) =>{
	try{
		let b
		let HWID =	request.body.HWID
		let Software = request.body.Software
		let Login = request.body.Login
		let Password = request.body.Password
		let Version = request.body.Version

		if ((Login == undefined) || (Login.length < 3) || (Login.length > 20)) throw new Error("Неверный логин!") 
		if ((Software == undefined) || (Software.length < 1) || (Software.length > 20)) throw new Error("Неверное ПО!")
		if ((Password == undefined) || (Password.length < 6) || (Password.length > 20)) throw new Error("Пароль должен быть длинее 6 символов и короче 20!")
		if ((HWID == undefined) || (HWID.length != 32)) throw new Error("Неверный HWID!")
		if ((Version == undefined) || (Version.length < 2)) throw new Error("Нет информации о версии!")	
		
		b = await knex("my_users").where({login: Login, password: Myhash(Password), hwid: HWID})  
		if (b.length == 0) throw new Error("Неверные учетные данные")
		let Fuser_id = b[0].user_id

		await knex("my_ips").insert({user_id: Fuser_id, software: Software, ip: request.get("x-forwarded-for")}) //request.get("X-Real-IP")
		b = await knex("my_softwares").where({soft_name: Software})
		if (b.length == 0) throw new Error("Неверное ПО!")		
		

		let myToken = Myhash(Math.random().toString()+":"+Date.now().toString())
		await knex("my_users").where({user_id: Fuser_id}).update({token: myToken})

		let mess = {
			TimesTamp: Math.floor(Date.now() / 1000),
			X_auth: myToken,
			Software: Software,
			Exp_time: "0",
			Payload: "clear",
			Update: (Version != b[0].version)  
		}
		let resp = await knex("my_softwares_"+b[0].soft_id).where({user_id: Fuser_id})
		if ( (resp.length != 0) && ( (resp[0].exp_time > Math.floor(Date.now() / 1000) ) || (resp[0].exp_time == 'LIFETIME') ) ) {
			mess.Exp_time = resp[0].exp_time
			mess.Payload = b[0].payload
		}		

		response.send({payload: key.encryptPrivate(mess, 'base64')}) 
	} catch (err){
		response.send({Mess: err.message})	
	}	
})

app.post('/api/activate', async (request, response) =>{
	try{
		let b
		let Key = request.body.Key;
		let HWID = request.body.HWID
		let AUTH = request.get("x-auth")

		if ((HWID == undefined) || (HWID.length != 32)) throw new Error("Неверный HWID!")
		if ((Key == undefined) || (Key.length != 48)) throw new Error("Неверный ключ!")
		if ((AUTH == undefined) || (AUTH.length != 64)) throw new Error("Неверный токен!")

		b = await knex("my_users").where({token: AUTH})
		if (b.length == 0) throw new Error("Несуществующий токен!")
		let Fuser_id = b[0].user_id
		
		b = await knex("my_keys").where({mkey: Key})
		if (b.length == 0) throw new Error("Неверный или использованный ключ!")
		let Fsoft_id = b[0].soft_id
		let Ftime = b[0].time
		let nowDate = Math.floor(Date.now() / 1000)

		await knex("my_activated_keys").insert({mkey: Key, soft_id: Fsoft_id, time: Ftime, user_id: Fuser_id});
		await knex("my_keys").where({mkey: Key}).del()

		b = await knex("my_softwares_"+Fsoft_id).where({user_id: Fuser_id})
		let res_time
		if (b.length == 0) {
			res_time = nowDate+Ftime*86400
			await knex("my_softwares_"+Fsoft_id).insert({user_id: Fuser_id, exp_time: res_time})				
		} else {
			res_time = (b[0].exp_time > nowDate) ? Number(b[0].exp_time)+Ftime*86400 : nowDate+Ftime*86400  			
			await knex("my_softwares_"+Fsoft_id).where({user_id: Fuser_id}).update({exp_time: res_time})
		}

		b = await knex("my_softwares").where({soft_id: Fsoft_id})
		let mess = {
			TimesTamp: Math.floor(Date.now() / 1000),
			Software: b[0].soft_name,
			Exp_time: res_time.toString(),
			Payload: b[0].payload  
		}

		response.send({payload: key.encryptPrivate(mess, 'base64')}) 	
	} catch (err){
		response.send({Mess: err.message})
	}
})

app.post('/api/signup', (request, response) =>{
	try{
		let HWID =	request.body.HWID
		let Software = request.body.Software
		let Login = request.body.Login
		let Password = request.body.Password	

		if ((Login == undefined) || (Login.length < 3) || (Login.length > 20)) throw new Error("Неверный логин!") 
		if ((Software == undefined) || (Software.length < 1) || (Software.length > 20)) throw new Error("Неверное ПО!")
		if ((Password == undefined) || (Password.length < 6) || (Password.length > 20)) throw new Error("Пароль должен быть длинее 6 символов и короче 20!")
		if ((HWID == undefined) || (HWID.length != 32)) throw new Error("Неверный HWID!")
		
		knex("my_users").insert({login: Login, password: Myhash(Password), hwid: HWID, reg_ip: request.get("x-forwarded-for"), reg_software: Software})
		.then(res =>  response.send({Mess: "Аккаунт был зарегестрирован!"}))
		.catch(res => response.send({Mess: "Ошибка регистрации!"}))

	} catch (err){
		response.send({Mess: err.message})	
	}
})

app.post('/api/sendReport', (request, response) =>{
	try{
		let HWID =	request.body.HWID
		let Software = request.body.Software
		let Login = request.body.Login
		let Report = request.body.Report	

		if ((Login == undefined) || (Login.length < 3) || (Login.length > 20)) throw new Error("Неверный логин!") 
		if ((Software == undefined) || (Software.length < 1) || (Software.length > 20)) throw new Error("Неверное ПО!")
		if ((Report == undefined) || (Report.length < 5)) throw new Error("Репорт должен быть немного больше!")
		if ((HWID == undefined) || (HWID.length != 32)) throw new Error("Неверный HWID!")
		if (Report.length >300) throw new Error("Слишком длинный репорт!")		
	
		Axios.get(encodeURI(`https://api.telegram.org/bot${conf.authToken}/sendMessage?chat_id=${conf.chat_id}&text=Username:${Login}\nHWID:${HWID}\nSoftware:${Software}\nReportMessage:${Report}`))
		.then(ress => response.send({Mess: 'Репорт отправлен!'}))
		.catch(err => response.send({Mess: 'Попробуйте позднее!'}))

	} catch (err){
		response.send({Mess: err.message})	
	}
})

app.post('/update', async (request, response) =>{
	try{
		let HWID =	request.body.HWID;
		let Software = request.body.Software
		let AUTH = request.get("x-auth")

		if ((HWID == undefined) || (HWID.length != 32)) throw new Error("Неверный HWID!")
		if ((Software == undefined) || (Software.length < 1) || (Software.length > 20)) throw new Error("Неверное ПО!")
		if ((AUTH == undefined) || (AUTH.length != 64)) throw new Error("Неверный токен!")	

		b = await knex("my_users").where({token: AUTH, hwid: HWID})
		if (b.length == 0) throw new Error("Несуществующий токен или неверный HWID!")
		let Fuser_id = b[0].user_id

		b = await knex("my_softwares").where({soft_name: Software})
		if (b.length == 0) throw new Error("Неверное ПО!")

		response.sendFile(path.join(__dirname, 'softwares', Software+'.zip'))

	} catch (err){
		response.send({Mess: err.message})
	}

})


app.use((request, response) =>{
	response.status(404).send('404!')
})

console.log("-----| Initalizing HTTP |-----")
app.listen(conf.port, () =>{
	console.log("-----| Server is running |----")
	console.log("-----| 127.0.0.1:"+conf.port+" |--------")
}) 

//knex("my_keys").insert({mkey: "Y8S08D-SOLC2K-MTL1DT-QXG3ED-QGPO0A-E6QUW9-G11WY1", soft_id: 1, time: 10}).then()
