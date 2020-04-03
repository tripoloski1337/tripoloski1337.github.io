---
layout: post
title:  "tracking corona virus using react.js"
date:   2020-04-03 #13:52:01
categories: webdev
description: this article explains about reactjs.
tags: webdev react.js
---

in this tutorial i will use api from `https://api.kawalcorona.com/indonesia` , this is
from ethical hacker indonesia.

firstly we need to create our reactjs project
{% highlight bash %}
create-react-app tracking-covid19
cd tracking-covid19
{% endhighlight %}

after finish , we need to install `reactstrap` so our web app will look nicer
{% highlight bash %}
npm install --save bootstrap
npm install --save reactstrap react react-dom
{% endhighlight %}

open App.js inside `./src/App.js`

{% highlight react %}
import React from 'react';
import logo from './logo.svg';
import './App.css';

function App() {
  return (
    <div className="App">
      <header className="App-header">
        <img src={logo} className="App-logo" alt="logo" />
        <p>
          Edit <code>src/App.js</code> and save to reload.
        </p>
        <a
          className="App-link"
          href="https://reactjs.org"
          target="_blank"
          rel="noopener noreferrer"
        >
          Learn React
        </a>
      </header>
    </div>
  );
}

export default App;

{% endhighlight %}

we need to import everything we need from `reactstrap`

{% highlight react %}
import 'bootstrap/dist/css/bootstrap.css';
import { Container ,
         Card ,
         CardHeader ,
         CardFooter ,
         CardBody ,
         CardTitle ,
         CardText
         } from "reactstrap";
{% endhighlight %}

and change from `function App()` to `class App extends React.Component` , so our code will
look like this

{% highlight react %}
import React from 'react';
import logo from './logo.svg';
import './App.css';

import { Container ,
         Card ,
         CardHeader ,
         CardFooter ,
         CardBody ,
         CardTitle ,
         CardText ,
         Row
         } from "reactstrap";

class App extends React.Component {
    render(){
      return (
      <div className="App">
        <header className="App-header">
          <img src={logo} className="App-logo" alt="logo" />
          <p>
            Edit <code>src/App.js</code> and save to reload.
          </p>
          <a
            className="App-link"
            href="https://reactjs.org"
            target="_blank"
            rel="noopener noreferrer"
          >
            Learn React
          </a>
        </header>
      </div>
    );
  }
}

export default App;

{% endhighlight %}

now we have to store the api url and an array to a state.

{% highlight react %}
constructor(props){
  super(props);
  this.state = {
    data: [],
    urlApiProvince: "https://api.kawalcorona.com/indonesia/provinsi/"
  }
}
{% endhighlight %}

to call the api i use fetch inside `componentDidMount()`

{% highlight react %}
componentDidMount(){
  fetch(this.state.urlApiProvince)
    .then(response => response.json())
    .then(data => this.setState({data:data}));
}
{% endhighlight %}

now , we need to create another state called `loading` so the web will show
something till the url give us full response , so i add loading on `state` and set it
on `componentDidMount` , our code  will look like this
{% highlight react %}
constructor(props){
  super(props);
  this.state = {
    data: [],
    urlApiProvince: "https://api.kawalcorona.com/indonesia/provinsi/",
    isLoading:true,
  }
}
componentDidMount(){
  fetch(this.state.urlApiProvince)
    .then(response => response.json())
    .then(data => this.setState({data:data , isLoading:false}));
}
{% endhighlight %}

and create return for loading inside `render()`

{% highlight react %}
var { isLoading } = this.state;
  if(isLoading){
    return "<h1>loading</h1>";
  }
{% endhighlight %}

now we need to show all the data , we can use Card from reactstrap to make it
looks more friendly

{% highlight react %}
return (
  <Container>
      <div className="col-lg-12">
        <h1> Corona virus in indonesia </h1>
        <Row>
        {data.map((d , i) =>
          <div className="col-md-3">
            <Card>
              <CardHeader>{d.attributes.Provinsi}</CardHeader>
              <CardBody>
                <CardTitle>Corona virus in {d.attributes.Provinsi} </CardTitle>
                <CardText>
                <ul>
                  <li>Positif: {d.attributes.Kasus_Posi}</li>
                  <li>Sembuh: {d.attributes.Kasus_Semb}</li>
                  <li>Meninggal: {d.attributes.Kasus_Meni}</li>
                </ul>
                </CardText>
              </CardBody>
              <CardFooter>Footer</CardFooter>
            </Card>
            <br/>
          </div>
          )}
        </Row>
      </div>
  </Container>
);
{% endhighlight %}

full code :

{% highlight react %}
import React from 'react';
import logo from './logo.svg';
import 'bootstrap/dist/css/bootstrap.css';
import { Container ,
         Card ,
         CardHeader ,
         CardFooter ,
         CardBody ,
         CardTitle ,
         CardText ,
         Row
         } from "reactstrap";

class App extends React.Component {
    constructor(props){
      super(props);
      this.state = {
        data: [],
        urlApiProvince: "https://api.kawalcorona.com/indonesia/provinsi/",
        isLoading:true,
      }
    }

    componentDidMount(){
      fetch(this.state.urlApiProvince)
        .then(response => response.json())
        .then(data => this.setState({data:data , isLoading:false}));
    }

    render(){
      var { isLoading , data } = this.state;
      if(isLoading){
        return "<h1>loading</h1>";
      }
      return (
      <Container>
          <div className="col-lg-12">
            <h1> Corona virus in indonesia </h1>
            <Row>
            {data.map((d , i) =>
              <div className="col-md-3">
                <Card>
                  <CardHeader>{d.attributes.Provinsi}</CardHeader>
                  <CardBody>
                    <CardTitle>Corona virus in {d.attributes.Provinsi} </CardTitle>
                    <CardText>
                    <ul>
                      <li>Positif: {d.attributes.Kasus_Posi}</li>
                      <li>Sembuh: {d.attributes.Kasus_Semb}</li>
                      <li>Meninggal: {d.attributes.Kasus_Meni}</li>
                    </ul>
                    </CardText>
                  </CardBody>
                  <CardFooter>Footer</CardFooter>
                </Card>
                <br/>
              </div>
              )}
            </Row>
          </div>
      </Container>
    );
  }
}

export default App;

{% endhighlight %}

and this is our website will look like

<img src="/images/2020-04-03-220939_1365x683_scrot.png" />

you can download my code [here](https://github.com/tripoloski1337/covid19-reactjs)
