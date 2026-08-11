export interface GroundworkErrorBody {
  error: string;
  detail?: string;
}

export class GroundworkError extends Error {
  readonly status: number;
  readonly code: string | null;
  readonly detail: string | null;
  readonly headers: Headers;

  constructor(message: string, status: number, code: string | null, detail: string | null, headers: Headers) {
    super(message);
    this.name = 'GroundworkError';
    this.status = status;
    this.code = code;
    this.detail = detail;
    this.headers = headers;
  }
}

export async function parseErrorResponse(res: Response): Promise<GroundworkError> {
  let code: string | null = null;
  let detail: string | null = null;
  try {
    const body = (await res.json()) as GroundworkErrorBody;
    if (typeof body?.error === 'string') {
      code = body.error;
      if (typeof body.detail === 'string') {
        detail = body.detail;
      }
    }
  } catch {
    // non-JSON body; fall through with raw status
  }
  const statusText = code ?? res.statusText;
  return new GroundworkError(`Groundwork API error ${res.status}${statusText ? `: ${statusText}` : ''}`, res.status, code, detail, res.headers);
}
