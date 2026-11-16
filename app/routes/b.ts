export function action(req) {
  const body = req.body
  return eval(body)
}
