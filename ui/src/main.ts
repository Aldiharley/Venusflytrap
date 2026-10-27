import '@fontsource-variable/inter';
import '@fontsource/jetbrains-mono/400.css';
import './styles/tokens.css';
import './styles/base.css';
import { mount } from 'svelte';
import App from './App.svelte';
import { theme } from './lib/state/theme.svelte';

theme.apply();
const target = document.getElementById('app');
if (target) mount(App, { target });
