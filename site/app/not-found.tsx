export default function NotFound() {
  return <main className="not-found"><span className="overline">404 / NOT FOUND</span><h1>Beyond the boundary.</h1><p>This page could not be found.</p><a className="arrow-link" href={`${process.env.NEXT_PUBLIC_BASE_PATH || ""}/`}>Return home ↗</a></main>;
}
