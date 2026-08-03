const units = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ']
const filePlural = new Intl.PluralRules('ru-RU')

export function formatBytes(bytes: number): string {
  let value = bytes
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit += 1
  }
  const precision = unit === 0 ? 0 : 1
  return `${value.toLocaleString('ru-RU', {
    maximumFractionDigits: precision,
    minimumFractionDigits: precision,
  })} ${units[unit]}`
}

export function formatFileCount(files: number): string {
  const plural = filePlural.select(files)
  const noun = plural === 'one' ? 'файл' : plural === 'few' ? 'файла' : 'файлов'
  return `${files.toLocaleString('ru-RU')} ${noun}`
}

export function shortenPath(path: string): string {
  if (path.length <= 58) return path
  const separator = path.includes('\\') ? '\\' : '/'
  if (path.startsWith('\\\\')) {
    const [server, share, ...tail] = path.slice(2).split('\\')
    if (server && share && tail.length > 0) {
      return `\\\\${server}\\${share}\\…\\${tail.slice(-2).join('\\')}`
    }
  }
  const parts = path.split(separator)
  if (parts.length < 3) return `…${path.slice(-55)}`
  return `${parts[0]}${separator}…${separator}${parts.slice(-2).join(separator)}`
}
