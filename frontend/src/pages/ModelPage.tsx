/**
 * The "Model & performance" page.
 */

import ModelInfoPanel from '../components/ModelInfoPanel';

export default function ModelPage() {
  return (
    <div className="page">
      <section className="panel panel--hero">
        <h2 className="panel__title">How the verdict is produced</h2>
        <p className="panel__note">
          The classifier is a supervised model trained on a labelled dataset of real URLs. Every
          number below was measured during the training run on a held-out test partition that
          was excluded from model fitting and from threshold selection. The dashboard never
          displays a metric that the backend did not actually record.
        </p>
      </section>

      <ModelInfoPanel />
    </div>
  );
}
