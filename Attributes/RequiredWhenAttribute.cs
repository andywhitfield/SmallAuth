using System.ComponentModel.DataAnnotations;

namespace SmallAuth.Attributes
{
    public class RequiredWhenAttribute : ValidationAttribute
    {
        private readonly string _dependentField;

        public RequiredWhenAttribute(string dependentField)
        {
            _dependentField = dependentField;
        }
        
        protected override ValidationResult IsValid(object value, ValidationContext validationContext)
        {
            var dependentFieldProp = validationContext.ObjectType.GetProperty(_dependentField);
            var dependentFieldVal = dependentFieldProp?.GetValue(validationContext.ObjectInstance)?.ToString();
            if (string.IsNullOrEmpty(dependentFieldVal))
                return ValidationResult.Success;

            var thisVal = value as string;
            return string.IsNullOrEmpty(thisVal) ? new ValidationResult("Value is required.") : ValidationResult.Success;
        }
    }
}