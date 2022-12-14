# cinema-app

### :mag_right: Overview
This project introduces knowledge of technologies such as Hibernate and Spring (Spring MVC, Spring security and Spring Core)

### :paperclip: Project description
In the project uses connection to DB by Spring. Implementation of N-tier architecture. And uses of Spring MVC to launch project on web service.

Project has structure:

- /register for registration new users
- /cinema-halls for get all cinema halls from the DB and post new cinema hall to DB  
- /movies same as /cinema-halls
- /movie-sessions {
  1. for post new movie sessions
  2. /available for get all available movies sessions by a certain date
  3. put to update certain movie session by id
  4. and delete some movie session by id  
}
- /orders to get orders history by authenticated user
- /orders/complete to complete shopping cart by authenticated user
- /shopping-carts/by-user to get information about shopping cart by authenticated user
- /shopping-carts/movie-sessions to put into shopping cart new ticket
- /users/by-email to find user by same email

### :straight_ruler: Project has 3-tier architecture

- Controller layer (Representing of endpoints)
- Service layer
- Data access object layer


### :books: Technologies used in project

- Java v.11
- Apache Tomcat
- MySQL
- Maven
- Hibernate
- Spring Core
- Spring MVC
- Spring Security

### :running: To run project you should
1. Install MySQL and Apache Tomcat version 9.
2. Configure Apache Tomcat for your IDE.
3. Configure db.properties with your URL, USERNAME, PASSWORD, JDBC_DRIVER.
4. In DataInitializer i'm already created user with fields {"email":"admin@i.ua", "password":"admin123", "role":"ADMIN"} 