import { createApp } from 'vue'
import { createRouter, createWebHashHistory } from 'vue-router'
import './style.css'
import App from './App.vue'
import Home from './views/Home.vue'
import Project from './views/Project.vue'
import Ctf from './views/Ctf.vue'

const router = createRouter({
  history: createWebHashHistory(),
  routes: [
    { path: '/', component: Home },
    { path: '/p/:id', component: Project, props: true },
    { path: '/ctf/:id', component: Ctf, props: true },
  ],
})

createApp(App).use(router).mount('#app')
