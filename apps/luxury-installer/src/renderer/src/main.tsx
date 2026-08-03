import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'

import App from './App'
import { createTauriBridge } from './tauri-bridge'
import './styles.css'

const bridge = createTauriBridge()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App bridge={bridge} />
  </StrictMode>,
)
