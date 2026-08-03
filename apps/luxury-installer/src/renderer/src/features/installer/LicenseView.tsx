import { Check, FileText } from 'lucide-react'

interface LicenseViewProps {
  name: string
  publisher: string
  license: string
  accepted: boolean
  onAccepted(value: boolean): void
  onBack(): void
  onInstall(): void
}

export function LicenseView({
  name,
  publisher,
  license,
  accepted,
  onAccepted,
  onBack,
  onInstall,
}: LicenseViewProps) {
  return (
    <section className="screen screen--license" aria-labelledby="license-title">
      <header className="screen__header">
        <div>
          <h1 id="license-title" data-view-heading tabIndex={-1}>
            Лицензионное соглашение
          </h1>
          <p>
            {name} · {publisher}
          </p>
        </div>
      </header>

      <div className="license-document" tabIndex={0} aria-label="Текст лицензионного соглашения">
        <pre>{license}</pre>
      </div>

      <label className="trust-consent license-consent">
        <input
          type="checkbox"
          checked={accepted}
          onChange={(event) => onAccepted(event.currentTarget.checked)}
        />
        <span className="trust-consent__check" aria-hidden="true">
          <Check size={14} strokeWidth={3} />
        </span>
        <FileText size={19} aria-hidden="true" />
        <span>
          <strong>Я принимаю условия соглашения.</strong>
          <small>Без явного согласия Rust не начнёт установку.</small>
        </span>
      </label>

      <footer className="screen__actions">
        <button className="secondary-button" type="button" onClick={onBack}>
          Назад
        </button>
        <button className="primary-button" type="button" disabled={!accepted} onClick={onInstall}>
          Принять и продолжить
        </button>
      </footer>
    </section>
  )
}
