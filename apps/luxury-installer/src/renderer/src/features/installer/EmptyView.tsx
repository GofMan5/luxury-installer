import { SquareDashed } from 'lucide-react'

export function EmptyView() {
  return (
    <section className="screen empty-screen" aria-labelledby="empty-title">
      <SquareDashed className="empty-screen__spinner spin" size={28} aria-hidden="true" />
      <h1 id="empty-title" data-view-heading tabIndex={-1}>Подготовка установки</h1>
      <p>Проверяем встроенные файлы…</p>
    </section>
  )
}
