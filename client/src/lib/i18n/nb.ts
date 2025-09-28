// Norwegian (Bokmål) localization strings
export const nb = {
  // Header & Navigation
  appName: 'TryggLink',
  tagline: 'Sikkerhetsskanner',
  nav: {
    home: 'Hjem',
    fileScan: 'Filskanning',
    dashboard: 'Dashboard',
    signIn: 'Logg inn'
  },

  // URL Scanner
  urlScanner: {
    title: 'Sjekk om en lenke',
    titleHighlight: 'er trygg før du klikker',
    description: 'Få umiddelbar sikkerhetsvurdering for URLer og filer. Resultatene er indikatorer — bruk alltid sunn fornuft.',
    placeholder: 'https://eksempel.no/mistenkelig-lenke',
    scanButton: 'Sjekk nå',
    scanning: 'Analyserer URL-sikkerhet...',
    results: 'Skanneresultater',
    riskScore: 'Risikovurdering',
    verdict: {
      safe: 'Trygg',
      suspicious: 'Mistenkelig',
      malicious: 'Ondsinnet'
    }
  },

  // File Scanner
  fileScanner: {
    title: 'Skann filer for malware',
    description: 'Last opp filer for å sjekke for virus, trojaner og annen ondsinnet programvare ved hjelp av flere sikkerhetsmotorer.',
    dropZoneText: 'Dra en fil hit eller velg fra disk',
    uploadButton: 'Velg fil',
    scanning: 'Skanner...',
    maxSize: 'Maks 32MB',
    supportedTypes: 'Støtte for .exe, .zip, .pdf, .docx og andre filtyper'
  },

  // Admin Dashboard
  admin: {
    title: 'Administrasjons-dashboard',
    description: 'Overvåk skanneaktivitet og systemhelse',
    stats: {
      totalScans: 'Totalt antall skanninger',
      maliciousDetected: 'Ondsinnede oppdaget',
      errorRate: 'Feilrate',
      activeUsers: 'Aktive brukere'
    },
    recentScans: 'Nylige skanninger',
    exportData: 'Eksporter data',
    refresh: 'Oppdater',
    viewDetails: 'Vis detaljer'
  },

  // Security Checks
  securityChecks: {
    googleSafeBrowsing: 'Google Safe Browsing',
    ipReputation: 'IP-omdømme',
    domainAge: 'Domenalder',
    domainAnalysis: 'Domeneanalyse',
    heuristicAnalysis: 'Heuristisk analyse',
    urlAnalysis: 'URL-analyse'
  },

  // Status Messages
  status: {
    clean: 'Ren',
    malicious: 'Ondsinnet',
    suspicious: 'Mistenkelig',
    error: 'Feil',
    unavailable: 'Utilgjengelig',
    unknown: 'Ukjent'
  },

  // Results Modal
  results: {
    riskScore: 'Risikoscore',
    securityChecks: 'Sikkerhetssjekker',
    domainInformation: 'Domeinformasjon',
    fileInformation: 'Filinformasjon',
    registrar: 'Registrator',
    ipAddress: 'IP-adresse',
    country: 'Land',
    fileSize: 'Filstørrelse',
    fileHash: 'Filhash',
    analysisDetails: 'Analysedetaljer',
    visitSite: 'Besøk nettsted',
    reportFalsePositive: 'Rapporter falsk positiv',
    disclaimer: 'TryggLink gir kun en indikasjon. Ikke juridisk bevis. Ved mistanke om svindel, kontakt din bank/politi.'
  },

  // Main Interface
  main: {
    fileTab: 'FIL',
    urlTab: 'URL',
    chooseFile: 'Velg fil',
    enterUrl: 'Skriv inn URL',
    urlPlaceholder: 'https://example.com',
    analyzeButton: 'Analyser',
    subtitle: 'Analyser mistenkelige filer, domener, IP-er og URL-er for å oppdage skadelig programvare og andre sikkerhetsbrudd'
  },

  // Common UI
  common: {
    loading: 'Laster...',
    error: 'Feil',
    success: 'Suksess',
    cancel: 'Avbryt',
    close: 'Lukk',
    save: 'Lagre',
    delete: 'Slett',
    edit: 'Rediger',
    back: 'Tilbake',
    next: 'Neste',
    previous: 'Forrige',
    search: 'Søk',
    filter: 'Filtrer',
    sort: 'Sorter',
    date: 'Dato',
    time: 'Tid',
    type: 'Type',
    result: 'Resultat',
    score: 'Poengsum',
    action: 'Handling',
    unknown: 'Ukjent'
  },

  // Error Messages
  errors: {
    invalidUrl: 'Ugyldig URL-format',
    scanFailed: 'Skanning mislyktes',
    networkError: 'Nettverksfeil',
    fileTooBig: 'Filen er for stor',
    fileTooLargeDescription: 'Vennligst velg en fil mindre enn 32MB',
    unsupportedFileType: 'Filtypen støttes ikke',
    uploadFailed: 'Opplasting mislyktes',
    noRecentScans: 'Ingen nylige skanninger funnet'
  },

  // Trends and statistics
  trends: {
    fromLastWeek: 'fra forrige uke',
    increaseArrow: '+',
    decreaseArrow: '-'
  },

  // Footer
  footer: {
    description: 'Beskytter brukere mot ondsinnede URLer og filer med omfattende sikkerhetsanalyse og sanntids trusseldeteksjon.',
    product: 'Produkt',
    productLinks: {
      urlScanner: 'URL-skanner',
      fileScanner: 'Filskanner',
      apiAccess: 'API-tilgang',
      enterprise: 'Bedriftsløsninger'
    },
    legal: 'Juridisk',
    legalLinks: {
      privacyPolicy: 'Personvernerklæring',
      termsOfService: 'Vilkår for bruk',
      contact: 'Kontakt',
      support: 'Kundestøtte'
    },
    copyright: '© 2024 TryggLink. Alle rettigheter forbeholdt.',
    disclaimer: 'Ved å sende inn data ovenfor, godtar du våre Tjenestevilkår og Personvernregler, og delingen av din prøveinnsending med sikkerhetsmiljøet. Ikke send inn personlig informasjon; vi er ikke ansvarlige for innholdet i din innsending.',
    learnMore: 'Lær mer'
  }
} as const;

export type TranslationKey = keyof typeof nb;